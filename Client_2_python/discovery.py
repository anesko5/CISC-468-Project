import socket
import time
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
import threading
from zeroconf import Zeroconf, ServiceBrowser, ServiceInfo
SERVICE_TYPE = "_cisc468p2p._tcp.local."

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


def start_raw_server(listen_ip, listen_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((listen_ip, listen_port))
        sock.listen(1)
        print(f"[*] Listening on {listen_ip}:{listen_port}...")
        
        conn, addr = sock.accept()
        with conn:
            print(f"[+] Connected to {addr}")
            execute_handshake(conn)

def connect_to_peer_raw(peer_ip, peer_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        print(f"[*] Connecting to {peer_ip}:{peer_port}...")
        sock.connect((peer_ip, peer_port))
        print(f"[+] Connected to {peer_ip}")
        execute_handshake(sock)

def execute_handshake(sock):
    # 1. Generate Ephemeral Key
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_public_key = ephemeral_private_key.public_key()
    
    # X25519 keys are exactly 32 bytes in raw format
    pub_bytes = ephemeral_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    
    # 2. Exchange Keys over TCP
    sock.sendall(pub_bytes)
    peer_pub_bytes = sock.recv(32)
    
    if len(peer_pub_bytes) != 32:
        print("[-] Handshake failed: Invalid key length")
        return
        
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
    
    # 3. Calculate Shared Secret
    shared_secret = ephemeral_private_key.exchange(peer_public_key)
    
    # 4. Derive AES-256 Session Key using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None, 
        info=b"cisc468-p2p-file-transfer" 
    )
    session_key = hkdf.derive(shared_secret)
    
    print(f"[+] Perfect Forward Secrecy established. Session Key: {session_key.hex()[:10]}...")

class PeerListener:
    """This class handles callbacks when a peer is discovered or leaves."""
    
    def __init__(self, own_name, listen_port):
        self.own_name = own_name
        self.local_ip = get_local_ip()
        self.listen_port = listen_port

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
            
            # Tie-breaker to assign Server/Client roles for the raw TCP socket
            if self.local_ip > peer_ip:
                print("[*] I am the Server. Starting listener...")
                threading.Thread(target=start_raw_server, args=(self.local_ip, self.listen_port)).start()
            else:
                print("[*] I am the Client. Connecting to peer...")
                time.sleep(1)  # Small delay to ensure the server is ready
                threading.Thread(target=connect_to_peer_raw, args=(peer_ip, peer_port)).start()

    def update_service(self, zeroconf, type_, name):
        pass


def main():
    local_ip = get_local_ip()
    listen_port = 5000  # The port your Python TCP server will eventually listen on
    node_name = f"PythonClient-{local_ip.replace('.', '-')}.{SERVICE_TYPE}"

    print(f"Starting P2P Node on {local_ip}:{listen_port}...")

    # 2. Setup the ZeroConf object
    zc = Zeroconf()

    # 3. Register (Advertise) our Python client to the local network
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

    # 4. Browse (Listen) for other peers (like the Go client)
    listener = PeerListener(own_name=node_name, listen_port=listen_port) 
    browser = ServiceBrowser(zc, SERVICE_TYPE, listener)

    try:
        print("Listening for peers... (Press Ctrl+C to exit)")
        # Keep the main thread alive while background threads handle mDNS
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down node...")
    finally:
        # Clean up and unregister our service from the network
        zc.unregister_service(info)
        zc.close()
        print("Offline.")





if __name__ == "__main__":
    main()

