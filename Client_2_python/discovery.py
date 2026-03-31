import socket
import time
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


class PeerListener:
    """This class handles callbacks when a peer is discovered or leaves."""
    
    def __init__(self, own_name):
        self.own_name = own_name

    def remove_service(self, zeroconf, type_, name):
        if name != self.own_name:
            print(f"[-] Peer disconnected: {name}")

    def add_service(self, zeroconf, type_, name):
        # Ignore our own broadcast
        if name == self.own_name:
            return
            
        info = zeroconf.get_service_info(type_, name)
        if info:
            addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
            port = info.port
            print(f"[+] Peer discovered: {name}")
            print(f"    IP: {addresses[0]} | Port: {port}")
            # Trigger handshake logic here later

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
        server="python-peer.local."
    )
    
    print(f"Advertising service: {node_name}")
    zc.register_service(info)

    # 4. Browse (Listen) for other peers (like the Go client)
    listener = PeerListener(own_name=node_name) 
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

