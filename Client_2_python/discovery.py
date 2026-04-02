import socket
import time
import os
import threading
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from zeroconf import Zeroconf, ServiceBrowser, ServiceInfo
from cryptography.hazmat.primitives.asymmetric import ed25519
import hashlib
import json
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

SERVICE_TYPE = "_cisc468p2p._tcp.local."
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def load_keys():
    """Loads your private key and all trusted peer public keys."""
    key_path = os.path.join(BASE_DIR, "my_identity_key.pem")
    trusted_dir = os.path.join(BASE_DIR, "trusted_peers")
    
    try:
        with open(key_path, "rb") as f:
            my_priv_key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        print(f"[-] Error: {key_path} not found.")
        return None, None

    trusted_peers = {}
    os.makedirs(trusted_dir, exist_ok=True)
    
    for filename in os.listdir(trusted_dir):
        if filename.endswith(".pem"):
            with open(os.path.join(trusted_dir, filename), "rb") as f:
                pub_key = serialization.load_pem_public_key(f.read())
                trusted_peers[filename] = pub_key
                
    print(f"[*] Loaded {len(trusted_peers)} trusted peers.")
    return my_priv_key, trusted_peers


def start_raw_server(listen_ip, listen_port, my_priv_key, trusted_peers):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((listen_ip, listen_port))
        sock.listen(1)
        print(f"[*] Listening on {listen_ip}:{listen_port}...")
        
        conn, addr = sock.accept()
        with conn:
            print(f"[+] Connected to {addr}")
            execute_handshake(conn, my_priv_key, trusted_peers)

def connect_to_peer_raw(peer_ip, peer_port, my_priv_key, trusted_peers):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        print(f"[*] Connecting to {peer_ip}:{peer_port}...")
        sock.connect((peer_ip, peer_port))
        print(f"[+] Connected to {peer_ip}")
        execute_handshake(sock, my_priv_key, trusted_peers)


def execute_handshake(sock, my_identity_private_key, trusted_peers):
    # 1. Prepare keys
    my_id_pub_bytes = my_identity_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    eph_pub_bytes = ephemeral_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    
    # 2. Sign and send (128 bytes total)
    signature = my_identity_private_key.sign(eph_pub_bytes)
    sock.sendall(my_id_pub_bytes + eph_pub_bytes + signature)
    
    # 3. Receive peer data
    peer_data = sock.recv(128)
    if len(peer_data) != 128:
        print("[-] Handshake failed: Invalid data length")
        sock.close()
        return
        
    peer_id_bytes = peer_data[:32]
    peer_eph_bytes = peer_data[32:64]
    peer_signature = peer_data[64:]
    
    peer_id_pub_key = ed25519.Ed25519PublicKey.from_public_bytes(peer_id_bytes)
    
    # 4. Verify Identity
    authenticated_peer = None
    for name, pub_key in trusted_peers.items():
        if pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw) == peer_id_bytes:
            try:
                pub_key.verify(peer_signature, peer_eph_bytes)
                authenticated_peer = name
                break
            except Exception:
                pass

    # 5. TOFU Logic
    if not authenticated_peer:
        fingerprint = hashlib.sha256(peer_id_bytes).hexdigest()[:12]
        trust = input(f"\n[?] Unknown peer detected (Fingerprint: {fingerprint}). Trust on first use? (y/n): ")
        
        if trust.strip().lower() == 'y':
            try:
                peer_id_pub_key.verify(peer_signature, peer_eph_bytes)
                filename = f"peer_{fingerprint}.pem"
                filepath = os.path.join(BASE_DIR, "trusted_peers", filename)                
                with open(filepath, "wb") as f:
                    f.write(peer_id_pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
                
                trusted_peers[filename] = peer_id_pub_key
                authenticated_peer = filename
                print(f"[+] Saved new peer to {filepath}")
            except Exception:
                print("[-] Invalid signature from unknown peer. Connection dropped.")
                sock.close()
                return
        else:
            print("[-] Connection rejected by user.")
            sock.close()
            return

    print(f"[+] Peer authenticated as: {authenticated_peer}")

    # 6. Derive Session Key
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_eph_bytes)
    shared_secret = ephemeral_private_key.exchange(peer_public_key)
    
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"cisc468-p2p-file-transfer")
    session_key = hkdf.derive(shared_secret)
    
    print(f"[+] Session Key Established!")

   # Initialize separate memory queues for uploads and downloads
    pending_uploads = []
    pending_downloads = {} # Maps filename -> b64_data payload

    # Start the Receive Thread
    threading.Thread(
        target=receive_loop, 
        args=(sock, session_key, pending_uploads, pending_downloads), 
        daemon=True
    ).start()
    
    # Run the UI Thread
    user_interface_loop(sock, session_key, pending_uploads, pending_downloads)


class PeerListener:
    def __init__(self, own_name, listen_port, my_priv_key, trusted_peers):
        self.own_name = own_name
        self.local_ip = get_local_ip()
        self.listen_port = listen_port
        self.my_priv_key = my_priv_key
        self.trusted_peers = trusted_peers

    def remove_service(self, zeroconf, type_, name):
        if name != self.own_name:
            print(f"[-] Peer disconnected: {name}")

    def add_service(self, zeroconf, type_, name):
        if name == self.own_name:
            return
            
        info = zeroconf.get_service_info(type_, name)
        if info:
            peer_ip = socket.inet_ntoa(info.addresses[0])
            peer_port = info.port
            print(f"[+] Peer discovered: {peer_ip}:{peer_port}")
            
            if self.local_ip > peer_ip:
                print("[*] I am the Server. Starting listener...")
                threading.Thread(target=start_raw_server, args=(self.local_ip, self.listen_port, self.my_priv_key, self.trusted_peers)).start()
            else:
                print("[*] I am the Client. Connecting to peer...")
                time.sleep(1) 
                threading.Thread(target=connect_to_peer_raw, args=(peer_ip, peer_port, self.my_priv_key, self.trusted_peers)).start()

    def update_service(self, zeroconf, type_, name):
        pass


def encrypt_message(session_key, plaintext_bytes):
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)  
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return nonce + ciphertext  

def decrypt_message(session_key, encrypted_payload):
    aesgcm = AESGCM(session_key)
    nonce = encrypted_payload[:12]
    ciphertext = encrypted_payload[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


def receive_loop(sock, session_key, pending_uploads, pending_downloads):
    while True:
        try:
            raw_msglen = recvall(sock, 4)
            if not raw_msglen:
                break 
            
            msglen = struct.unpack('!I', raw_msglen)[0]
            
            encrypted_payload = recvall(sock, msglen)
            if not encrypted_payload:
                break
                
            plaintext_bytes = decrypt_message(session_key, encrypted_payload)
            message = json.loads(plaintext_bytes.decode('utf-8'))
            
            handle_incoming_message(sock, session_key, message, pending_uploads, pending_downloads)
            
        except Exception as e:
            print(f"\n[-] Receive loop error: {e}")
            break
            
    print("\n[-] Connection closed by peer.")
    sock.close()
    os._exit(0)

def recvall(sock, n):
    """Helper function to cleanly read exactly n bytes from a TCP socket."""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def handle_incoming_message(sock, session_key, message, pending_uploads, pending_downloads):
    action = message.get("action")
    
    if action == "request_file":
        filename = message.get("filename")
        print(f"\n[PEER ALERT] Peer is requesting file: '{filename}'")
        print(f"             Type 'approve {filename}' or 'deny {filename}' to respond.")
        
        if filename not in pending_uploads:
            pending_uploads.append(filename)
            
        print("P2P> ", end="", flush=True) 

    elif action == "send_file":
        filename = message.get("filename")
        b64_data = message.get("data")
        
        if b64_data:
            print(f"\n[PEER ALERT] Peer sent a file: '{filename}'")
            print(f"             Type 'accept {filename}' or 'reject {filename}' to save to disk.")
            
            # Stage the file in memory
            pending_downloads[filename] = b64_data
        else:
            print(f"\n[-] Peer sent empty file data for '{filename}'")
            
        print("P2P> ", end="", flush=True)

    elif action == "request_list":
        print("\n[PEER] Peer requested your file list.")
        
        public_dir = os.path.join(BASE_DIR, "public_files")
        os.makedirs(public_dir, exist_ok=True)
        
        available_files = []
        for f in os.listdir(public_dir):
            if os.path.isfile(os.path.join(public_dir, f)) and not f.startswith('.'):
                available_files.append(f)
        
        resp_dict = {
            "action": "send_list",
            "data": available_files
        }
        
        payload_bytes = json.dumps(resp_dict).encode('utf-8')
        encrypted_payload = encrypt_message(session_key, payload_bytes)
        sock.sendall(struct.pack('!I', len(encrypted_payload)) + encrypted_payload)
        
        print("[*] Public file list automatically sent to peer.")
        print("P2P> ", end="", flush=True)

    elif action == "send_list":
        file_list = message.get("data", [])
        
        print("\n[+] Peer's Available Files:")
        if not file_list:
            print("    (Peer has no files available to share)")
        else:
            for f in file_list:
                print(f"    - {f}")
                
        print("P2P> ", end="", flush=True)

    else:
        print(f"\n[PEER] Unknown message action: {action}")
        print("P2P> ", end="", flush=True)


def send_file_to_peer(sock, session_key, filename):
    # Route the path into the public folder
    filepath = os.path.join(BASE_DIR, "public_files", filename)    
    try:
        with open(filepath, "rb") as f:
            file_bytes = f.read()
            
        b64_data = base64.b64encode(file_bytes).decode('utf-8')
        
        response_dict = {
            "action": "send_file",
            "filename": filename,
            "data": b64_data
        }
        
        payload_bytes = json.dumps(response_dict).encode('utf-8')
        encrypted_payload = encrypt_message(session_key, payload_bytes)
        length_prefix = struct.pack('!I', len(encrypted_payload))
        
        sock.sendall(length_prefix + encrypted_payload)
        print(f"\n[+] Successfully sent '{filename}' to peer.")
        
    except FileNotFoundError:
        print(f"\n[-] Error: '{filename}' does not exist in your public_files directory.")

def user_interface_loop(sock, session_key, pending_uploads, pending_downloads):
    print("\n[+] Secure Tunnel Ready.")
    print("Commands: request <file>, approve <file>, deny <file>, accept <file>, reject <file>, request_list, exit")
    
    while True:
        try:
            command = input("P2P> ").strip()
            if not command:
                continue
                
            parts = command.split(" ", 1)
            cmd = parts[0].lower()
            
            if cmd == "exit":
                sock.close()
                os._exit(0)
                
            elif cmd == "approve" and len(parts) == 2:
                filename = parts[1]
                if filename in pending_uploads:
                    pending_uploads.remove(filename)
                    send_file_to_peer(sock, session_key, filename)
                else:
                    print(f"[-] No pending upload request for '{filename}'.")
                    
            elif cmd == "deny" and len(parts) == 2:
                filename = parts[1]
                if filename in pending_uploads:
                    pending_uploads.remove(filename)
                    print(f"[*] Rejected upload request for '{filename}'.")
                else:
                    print(f"[-] No pending upload request for '{filename}'.")

            elif cmd == "accept" and len(parts) == 2:
                filename = parts[1]
                if filename in pending_downloads:
                    # Retrieve from memory, decode, and save securely
                    file_bytes = base64.b64decode(pending_downloads[filename])
                    safe_filename = f"received_{filename}"
                    with open(safe_filename, "wb") as f:
                        f.write(file_bytes)
                    del pending_downloads[filename]
                    print(f"[*] Saved '{filename}' to disk as '{safe_filename}'.")
                else:
                    print(f"[-] No pending download for '{filename}'.")

            elif cmd == "reject" and len(parts) == 2:
                filename = parts[1]
                if filename in pending_downloads:
                    del pending_downloads[filename] # Flush from memory
                    print(f"[*] Rejected and deleted incoming file '{filename}'.")
                else:
                    print(f"[-] No pending download for '{filename}'.")

            elif cmd == "request" and len(parts) == 2:
                filename = parts[1]
                req_dict = {"action": "request_file", "filename": filename}
                payload = json.dumps(req_dict).encode('utf-8')
                encrypted_payload = encrypt_message(session_key, payload)
                sock.sendall(struct.pack('!I', len(encrypted_payload)) + encrypted_payload)
                print(f"[*] Requested '{filename}' from peer...")

            elif cmd == "request_list":
                req_dict = {"action": "request_list"}
                payload = json.dumps(req_dict).encode('utf-8')
                encrypted_payload = encrypt_message(session_key, payload)
                sock.sendall(struct.pack('!I', len(encrypted_payload)) + encrypted_payload)
                print("[*] Requested file list from peer. Waiting for response...")
                
            else:
                print("[-] Unknown command or missing filename.")
                
        except Exception as e:
            print(f"[-] Interface error: {e}")
            break


def main():
    my_priv_key, trusted_peers = load_keys()
    if my_priv_key is None:
        return

    local_ip = get_local_ip()
    listen_port = 5000  
    node_name = f"PythonClient-{local_ip.replace('.', '-')}.{SERVICE_TYPE}"

    print(f"Starting P2P Node on {local_ip}:{listen_port}...")

    zc = Zeroconf()

    info = ServiceInfo(
        type_=SERVICE_TYPE,
        name=node_name,
        addresses=[socket.inet_aton(local_ip)],
        port=listen_port,
        properties={'version': '1.0', 'lang': 'python'},
        server=f"{local_ip.replace('.', '-')}.local." 
    )

    print(f"Advertising service: {node_name}")
    zc.register_service(info)

    listener = PeerListener(own_name=node_name, listen_port=listen_port, my_priv_key=my_priv_key, trusted_peers=trusted_peers) 
    browser = ServiceBrowser(zc, SERVICE_TYPE, listener)

    try:
        print("Listening for peers... (Press Ctrl+C to exit)")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down node...")
    finally:
        zc.unregister_service(info)
        zc.close()
        print("Offline.")

if __name__ == "__main__":
    main()
