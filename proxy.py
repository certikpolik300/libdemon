import socket
import socks  # PySocks library
import struct

class Proxy:
    def __init__(self, proxy_type=None, proxy_ip=None, proxy_port=None, username=None, password=None):
        self.proxy_type = proxy_type
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port
        self.username = username
        self.password = password

    def set_socks5_proxy(self, ip, port, username=None, password=None):
        self.proxy_type = "SOCKS5"
        self.proxy_ip = ip
        self.proxy_port = port
        self.username = username
        self.password = password

    def set_dtproto_proxy(self):
        self.proxy_type = "DTPROTO"
        self.proxy_ip = "megalodon"
        self.proxy_port = 53149
        self.username = "user"  # Replace with actual credentials
        self.password = "password"  # Replace with actual credentials

    def connect(self, host, port):
        if self.proxy_type == "SOCKS5":
            socks.set_default_proxy(socks.SOCKS5, self.proxy_ip, self.proxy_port, username=self.username, password=self.password)
            socket.socket = socks.socksocket
        elif self.proxy_type == "DTPROTO":
            self._dtproto_connect(host, port)

        # Connect to the host
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        return sock

    def _dtproto_connect(self, host, port):
        # DTProto connection setup
        print(f"Connecting to DTProto proxy at {self.proxy_ip}:{self.proxy_port}")
        # Example of custom protocol handshake
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.proxy_ip, self.proxy_port))
        # Send custom handshake
        handshake_message = f"CONNECT {host}:{port} DTPROTO/1.0\n"
        sock.sendall(handshake_message.encode())
        response = sock.recv(1024)
        if b"200 Connection established" not in response:
            raise ConnectionError("DTProto proxy connection failed")
        print("Connected to DTProto proxy")
        return sock

# Example usage
proxy = Proxy()
# User will set the proxy IP and port in their application for SOCKS5
# proxy.set_socks5_proxy("user_ip", user_port, "username", "password")
# Or use DTProto proxy
# proxy.set_dtproto_proxy()
# sock = proxy.connect("example.com", 80)
