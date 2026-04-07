from email.mime import message
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
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


SERVICE_TYPE = "_cisc468p2p._tcp.local."
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def get_local_storage_key():
    """Derives an AES key from a user password for local file encryption."""
    salt_path = os.path.join(BASE_DIR, "storage_salt.bin")
    
    if os.path.exists(salt_path):
        with open(salt_path, "rb") as f:
            salt = f.read()
    else:
        salt = os.urandom(16)
        with open(salt_path, "wb") as f:
            f.write(salt)
            

    password = input("\n Enter your Master Password to unlock local storage: ").encode('utf-8')
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password)

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


def start_raw_server(listen_ip, listen_port, my_priv_key, trusted_peers, local_storage_key):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((listen_ip, listen_port))
        sock.listen(1)
        print(f"[*] Listening on {listen_ip}:{listen_port}...")
        
        conn, addr = sock.accept()
        with conn:
            print(f"[+] Connected to {addr}")
            execute_handshake(conn, my_priv_key, trusted_peers, local_storage_key)

def connect_to_peer_raw(peer_ip, peer_port, my_priv_key, trusted_peers, local_storage_key):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        print(f"[*] Connecting to {peer_ip}:{peer_port}...")
        sock.connect((peer_ip, peer_port))
        print(f"[+] Connected to {peer_ip}")
        execute_handshake(sock, my_priv_key, trusted_peers, local_storage_key)


def execute_handshake(sock, my_identity_private_key, trusted_peers, local_storage_key):
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
    
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"P2P File Transfer")
    session_key = hkdf.derive(shared_secret)
    
    print(f"[+] Session Key Established!")

   # Initialize separate memory queues for uploads and downloads
    pending_uploads = []
    pending_downloads = {} # Maps filename -> b64_data payload
    requested_files = [] # Track requested files to correlate responses

    # Start the Receive Thread    
    threading.Thread(
        target=receive_loop, 
        args=(sock, session_key, pending_uploads, pending_downloads, requested_files, local_storage_key, trusted_peers, authenticated_peer), # Added trusted_peers
        daemon=True
    ).start()
        
    user_interface_loop(sock, session_key, pending_uploads, pending_downloads, requested_files, local_storage_key, my_identity_private_key, trusted_peers) # Added both keys


def recvall(sock, n):
    """Helper function to cleanly read exactly n bytes from a TCP socket."""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

class PeerListener:
    def __init__(self, own_name, listen_port, my_priv_key, trusted_peers, local_storage_key):
        self.own_name = own_name
        self.local_ip = get_local_ip()
        self.listen_port = listen_port
        self.my_priv_key = my_priv_key
        self.trusted_peers = trusted_peers
        self.local_storage_key = local_storage_key 

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
            
            my_address = f"{self.local_ip}:{self.listen_port}"
            peer_address = f"{peer_ip}:{peer_port}"
            
            if my_address > peer_address:
                print("[*] I am the Server. Starting listener...")
                threading.Thread(target=start_raw_server, args=(self.local_ip, self.listen_port, self.my_priv_key, self.trusted_peers, self.local_storage_key)).start()
            else:
                print("[*] I am the Client. Connecting to peer...")
                time.sleep(1) 
                threading.Thread(target=connect_to_peer_raw, args=(peer_ip, peer_port, self.my_priv_key, self.trusted_peers, self.local_storage_key)).start()

                

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


def sign_file_data(data, my_priv_key):
    """Hashes the file, signs it, and appends the fingerprint + signature."""
    # 1. Hash the original data
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    file_hash = digest.finalize()
    
    # 2. Sign the hash
    signature = my_priv_key.sign(file_hash)
    
    # 3. Get your 12-byte fingerprint
    my_pub_bytes = my_priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    fingerprint = hashlib.sha256(my_pub_bytes).hexdigest()[:12].encode('utf-8')
    
    # Return the bundled package: [Data] + [12-byte Fingerprint] + [64-byte Signature]
    return data + fingerprint + signature

def verify_and_strip_data(bundle, trusted_peers):
    """Verifies the attached signature and returns the clean file data."""
    if len(bundle) < 76:
        return False, "File is too small to contain a valid signature."
        
    original_data = bundle[:-76]
    fingerprint = bundle[-76:-64].decode('utf-8')
    signature = bundle[-64:]
    
    # 1. Hash the original data exactly as the creator did
    digest = hashes.Hash(hashes.SHA256())
    digest.update(original_data)
    file_hash = digest.finalize()
    
    # 2. Find the creator's public key in your trusted peers
    peer_filename = f"peer_{fingerprint}.pem"
    if peer_filename not in trusted_peers:
        return False, f"Unknown creator (Fingerprint: {fingerprint}). You do not trust this author."
        
    peer_pub_key = trusted_peers[peer_filename]
    
    # 3. Verify the signature
    try:
        peer_pub_key.verify(signature, file_hash)
        return True, original_data # Success! Return the clean data.
    except Exception:
        return False, "Signature verification failed! File was tampered with."

def receive_loop(sock, session_key, pending_uploads, pending_downloads, requested_files, local_storage_key, trusted_peers, current_peer_filename=None):
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
            
            handle_incoming_message(sock, session_key, message, pending_uploads, pending_downloads, requested_files, local_storage_key, trusted_peers, current_peer_filename)
            
        except Exception as e:
            print(f"\n[-] Receive loop error: {e}")
            break
            
    print("\n[-] Connection closed by peer.")
    sock.close()
    os._exit(0)

def handle_incoming_message(sock, session_key, message, pending_uploads, pending_downloads, requested_files, local_storage_key=None, trusted_peers=None, current_peer_filename=None):
    action = message.get("action")
    
    if action == "REQ_FILE":
        filename = message.get("filename")           
        print(f"\n[PEER ALERT] Peer is requesting file: '{filename}'")
        print(f"             Type 'approve {filename}' or 'deny {filename}' to respond.")
        
        if filename not in pending_uploads:
            pending_uploads.append(filename)
            
        print("P2P> ", end="", flush=True) 

    elif action == "SEND_FILE":
        filename = message.get("filename")
        b64_data = message.get("payload")
        
        if b64_data:
            print(f"\n[PEER ALERT] Peer sent a file: '{filename}'")
            print(f"             Type 'accept {filename}' or 'reject {filename}' to save to disk.")
            
            # Stage the file in memory
            pending_downloads[filename] = b64_data
        else:
            print(f"\n[-] Peer sent empty file data for '{filename}'")
            
        print("P2P> ", end="", flush=True)

    elif action == "REQ_LIST":
        print("\n[PEER] Peer requested your file list.")
        
        public_dir = os.path.join(BASE_DIR, "available_files")
        os.makedirs(public_dir, exist_ok=True)
        
        available_files = []
        for f in os.listdir(public_dir):
            if os.path.isfile(os.path.join(public_dir, f)) and not f.startswith('.'):
                available_files.append(f)

        resp_dict = {
            "action": "RES_LIST",
            "filelist": available_files
        }
        
        payload_bytes = json.dumps(resp_dict).encode('utf-8')
        encrypted_payload = encrypt_message(session_key, payload_bytes)
        
        length_prefix = struct.pack('!I', len(encrypted_payload))
        
        sock.sendall(length_prefix + encrypted_payload)
        
        print("[*] Public file list automatically sent to peer.")
        print("P2P> ", end="", flush=True)

    elif action == "RES_FILE":

        filename = message.get("filename")
        if message.get("filelist") == ["NOT_FOUND"]:
            print(f"\n[-] Peer Alert: The requested file '{filename}' was NOT FOUND on their system.")
            if filename in requested_files:
                requested_files.remove(filename) # Clean up your tracking list
            print("P2P> ", end="", flush=True)
            return
        
        b64_data = message.get("payload")
        if b64_data:
            print(f"\n[PEER ALERT] Peer sent a file: '{filename}'")
            if filename in requested_files:
                print(f"             This is a response to your request for '{filename}'.")
                requested_files.remove(filename) 
            else:
                print(f"             You did not request '{filename}'. It will not be downloaded.")
                return
        else:
            print(f"\n[-] Peer sent empty file data for '{filename}'")
            return

        file_bytes = base64.b64decode(b64_data)
        
        is_valid, result = verify_and_strip_data(file_bytes, trusted_peers)
        if not is_valid:
            print(f"\n[ SECURITY ALERT] {result}")
            print(f"[-] Dropping tampered file '{filename}'.")
            print("P2P> ", end="", flush=True)
            return

        safe_filename = f"received_{filename}"
        filepath = os.path.join(BASE_DIR, "available_files", safe_filename)
        
        # Encrypt the full signed bundle (file_bytes) so you can forward it to others later
        encrypted_file_bytes = encrypt_message(local_storage_key, file_bytes)

        with open(filepath, "wb") as f:   
            f.write(encrypted_file_bytes)
            
        print(f"[*] Signature verified! Saved '{filename}' to disk as '{safe_filename}'.")
        print("P2P> ", end="", flush=True)

    elif action == "KEY_MIGRATION":
        b64_key = message.get("payload")
        raw_key = base64.b64decode(b64_key)
        fingerprint = hashlib.sha256(raw_key).hexdigest()[:12]
        
        print("\n\n[KEY MIGRATION] Peer is migrating to a new identity key!")
        
        if current_peer_filename:
            old_filepath = os.path.join(BASE_DIR, "trusted_peers", current_peer_filename)
            if os.path.exists(old_filepath):
                os.remove(old_filepath)
                print(f"[*] Deleted compromised old key: {current_peer_filename}")
        
        print(f"[*] Automatically accepting new key (Fingerprint: {fingerprint}) over the network...")
        
        new_pub = ed25519.Ed25519PublicKey.from_public_bytes(raw_key)
        filename = f"peer_{fingerprint}.pem"
        filepath = os.path.join(BASE_DIR, "trusted_peers", filename)
        
        with open(filepath, "wb") as f:
            f.write(new_pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
            
        print(f"[+] New key saved as {filename}.")
        print("[!] Terminating current session to establish a fresh, secure tunnel with the new key.")
        print("    Please restart the application.")
        
        sock.close()
        os._exit(0)

    elif action == "RES_LIST":
        file_list = message.get("filelist", [])
        
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


def send_file_to_peer(sock, session_key, filename, local_storage_key):
    filepath = os.path.join(BASE_DIR, "available_files", filename)    
    try:
        with open(filepath, "rb") as f:
            encrypted_file_bytes = f.read()
        try:
            file_bytes = decrypt_message(local_storage_key, encrypted_file_bytes)
        except Exception:
                print(f"\n[-] Critical Error: Cannot decrypt '{filename}'. Invalid Master Password?")
                return    
        
        b64_data = base64.b64encode(file_bytes).decode('utf-8')
        
        response_dict = {
            "action": "SEND_FILE",
            "filename": filename,
            "payload": b64_data
        }
        
        payload_bytes = json.dumps(response_dict).encode('utf-8')
        encrypted_payload = encrypt_message(session_key, payload_bytes)
        length_prefix = struct.pack('!I', len(encrypted_payload))
        
        sock.sendall(length_prefix + encrypted_payload)
        print(f"\n[+] Successfully sent '{filename}' to peer.")
        
    except FileNotFoundError:
        print(f"\n[-] Error: '{filename}' does not exist in your available_files directory.")


def send_response_file_to_peer(sock, session_key, filename, local_storage_key):
    filepath = os.path.join(BASE_DIR, "available_files", filename)    
    
    # 1. Check if the file actually exists on the hard drive
    if not os.path.exists(filepath):
        print(f"\n[-] Error: '{filename}' not found. Sending 'NOT_FOUND' response to peer.")
        
        response_dict = {
            "action": "RES_FILE",
            "filename": filename,
            "filelist": ["NOT_FOUND"]
        }
        
        payload_bytes = json.dumps(response_dict).encode('utf-8')
        encrypted_payload = encrypt_message(session_key, payload_bytes)
        length_prefix = struct.pack('!I', len(encrypted_payload))
        
        sock.sendall(length_prefix + encrypted_payload)
        return 

    # 2. If it does exist, read, decrypt, and send it
    try:
        with open(filepath, "rb") as f:
            encrypted_file_bytes = f.read()
            
        try:
            file_bytes = decrypt_message(local_storage_key, encrypted_file_bytes)
        except Exception:
            print(f"\n[-] Critical Error: Cannot decrypt '{filename}'. Invalid Master Password?")
            return
            
        b64_data = base64.b64encode(file_bytes).decode('utf-8')
        
        response_dict = {
            "action": "RES_FILE",
            "filename": filename,
            "payload": b64_data 
        }
        
        payload_bytes = json.dumps(response_dict).encode('utf-8')
        encrypted_payload = encrypt_message(session_key, payload_bytes)
        length_prefix = struct.pack('!I', len(encrypted_payload))
        
        sock.sendall(length_prefix + encrypted_payload)
        print(f"\n[+] Successfully sent '{filename}' to peer.")
        
    except Exception as e:
        print(f"\n[-] Unexpected Error while sending file: {e}")


def perform_key_migration(sock, session_key):
    print("\n[*] Generating brand new Ed25519 Identity Key...")
    
    # 1. Generate new keys
    new_priv_key = ed25519.Ed25519PrivateKey.generate()
    new_pub_key = new_priv_key.public_key()
    
    # 2. Overwrite the old compromised keys on disk
    priv_path = os.path.join(BASE_DIR, "my_identity_key.pem")
    with open(priv_path, "wb") as f:
        f.write(new_priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    pub_path = os.path.join(BASE_DIR, "my_identity_public_key.pem")
    with open(pub_path, "wb") as f:
        f.write(new_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
    # 3. Package and encrypt the new public key for the peer
    pub_bytes = new_pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    b64_pub = base64.b64encode(pub_bytes).decode('utf-8')
    
    req_dict = {"action": "KEY_MIGRATION", "payload": b64_pub}
    payload = json.dumps(req_dict).encode('utf-8')
    encrypted_payload = encrypt_message(session_key, payload)
    
    # 4. Send the notification
    sock.sendall(struct.pack('!I', len(encrypted_payload)) + encrypted_payload)
    
    print("[+] Key migrated successfully and peer notified.")
    print("[!] The application will now exit to re-establish secure tunnels. Please restart.")
    
    # 5. Kill the compromised tunnel
    sock.close()
    os._exit(0)


def user_interface_loop(sock, session_key, pending_uploads, pending_downloads, requested_files, local_storage_key=None, my_priv_key=None, trusted_peers=None):
    print("\n[+] Secure Tunnel Ready.")
    print("Commands: send <file>, request <file>, approve <file>, deny <file>, accept <file>, reject <file>, request_list, import <file>, export <file>, migrate, exit")    
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
            
            elif cmd == "send" and len(parts) == 2:
                filename = parts[1]
                send_file_to_peer(sock, session_key, filename, local_storage_key)
                
            elif cmd == "approve" and len(parts) == 2:
                filename = parts[1]
                if filename in pending_uploads:
                    pending_uploads.remove(filename)
                    send_response_file_to_peer(sock, session_key, filename, local_storage_key)
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
                    signed_bytes = base64.b64decode(pending_downloads[filename])
                    
                    # --- OFFLINE VERIFICATION ---
                    is_valid, result = verify_and_strip_data(signed_bytes, trusted_peers)
                    if not is_valid:
                        print(f"\n[SECURITY ALERT] {result}")
                        print(f"[-] Dropping tampered file '{filename}'.")
                        del pending_downloads[filename]
                        continue
                    # ----------------------------

                    # If valid, encrypt the original signed bundle and save it
                    safe_filename = f"received_{filename}"
                    filepath = os.path.join(BASE_DIR, "available_files", safe_filename)
                    encrypted_file_bytes = encrypt_message(local_storage_key, signed_bytes)
                    
                    with open(filepath, "wb") as f:
                        f.write(encrypted_file_bytes)
                    del pending_downloads[filename]
                    print(f"[*] Signature verified! Saved as '{safe_filename}'.")   



            elif cmd == "import" and len(parts) == 2:
                source_filename = parts[1]
                source_path = os.path.join(BASE_DIR, source_filename)
                try:
                    with open(source_path, "rb") as f:
                        plaintext_bytes = f.read()
                        
                    # 1. Sign the file!
                    signed_bytes = sign_file_data(plaintext_bytes, my_priv_key)
                    
                    # 2. Encrypt the signed bundle for local storage
                    encrypted_bytes = encrypt_message(local_storage_key, signed_bytes)
                    
                    dest_path = os.path.join(BASE_DIR, "available_files", source_filename)
                    with open(dest_path, "wb") as f:
                        f.write(encrypted_bytes)
                    print(f"[*] Successfully signed, encrypted, and imported '{source_filename}'.")
                except FileNotFoundError:
                    print(f"[-] Error: Could not find '{source_filename}'.")

            elif cmd == "reject" and len(parts) == 2:
                filename = parts[1]
                if filename in pending_downloads:
                    del pending_downloads[filename] # Flush from memory
                    print(f"[*] Rejected and deleted incoming file '{filename}'.")
                else:
                    print(f"[-] No pending download for '{filename}'.")

            elif cmd == "request" and len(parts) == 2:
                filename = parts[1]
                req_dict = {"action": "REQ_FILE", "filename": filename}
                payload = json.dumps(req_dict).encode('utf-8')
                encrypted_payload = encrypt_message(session_key, payload)
                sock.sendall(struct.pack('!I', len(encrypted_payload)) + encrypted_payload)
                requested_files.append(filename) # Track requested file
                print(f"[*] Requested '{filename}' from peer...")

            elif cmd == "request_list":
                req_dict = {"action": "REQ_LIST"}
                payload = json.dumps(req_dict).encode('utf-8')
                encrypted_payload = encrypt_message(session_key, payload)
                sock.sendall(struct.pack('!I', len(encrypted_payload)) + encrypted_payload)
                print("[*] Requested file list from peer. Waiting for response...")
                

            elif cmd == "export" and len(parts) == 2:
                filename = parts[1]
                secure_path = os.path.join(BASE_DIR, "available_files", filename)
                try:
                    with open(secure_path, "rb") as f:
                        encrypted_bytes = f.read()
                    
                    # 1. Decrypt from local storage
                    signed_bytes = decrypt_message(local_storage_key, encrypted_bytes)
                    
                    # 2. Strip the 76-byte tail so it opens normally
                    clean_plaintext = signed_bytes[:-76]
                    
                    export_path = os.path.join(BASE_DIR, f"decrypted_{filename}")
                    with open(export_path, "wb") as f:
                        f.write(clean_plaintext)
                    print(f"[+] Exported '{filename}' natively as 'decrypted_{filename}'.")
                except FileNotFoundError:
                    print(f"[-] Error: '{filename}' not found.")


            elif cmd == "migrate":
                print("\n[!] WARNING: This will overwrite your Identity Key and terminate current sessions.")
                confirm = input("Are you sure your key is compromised? (y/n): ")
                if confirm.strip().lower() == 'y':
                    perform_key_migration(sock, session_key)

            else:
                print("[-] Unknown command or missing filename.")

            
                
        except Exception as e:
            print(f"[-] Interface error: {e}")
            break


def main():

    local_storage_key = get_local_storage_key()
    print("[+] Local storage unlocked.")
    my_priv_key, trusted_peers = load_keys()
    if my_priv_key is None:
        return

    local_ip = get_local_ip()
    listen_port = 5000  
    node_name = f"PythonClient-{listen_port}-{local_ip.replace('.', '-')}.{SERVICE_TYPE}"
    print(f"Starting P2P Node on {local_ip}:{listen_port}...")

    zc = Zeroconf()

    info = ServiceInfo(
        type_=SERVICE_TYPE,
        name=node_name,
        addresses=[socket.inet_aton(local_ip)],
        port=listen_port,
        properties={'version': '1.0', 'lang': 'python'},
        server=f"client-{listen_port}-{local_ip.replace('.', '-')}.local."    )

    print(f"Advertising service: {node_name}")
    zc.register_service(info)

    listener = PeerListener(own_name=node_name, listen_port=listen_port, my_priv_key=my_priv_key, trusted_peers=trusted_peers, local_storage_key=local_storage_key) 
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
