import socket
import hashlib
import os

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
            import socks  # PySocks library
            socks.set_default_proxy(socks.SOCKS5, self.proxy_ip, self.proxy_port, username=self.username, password=self.password)
            socket.socket = socks.socksocket
        elif self.proxy_type == "DTPROTO":
            self._dtproto_connect(host, port)

        # Connect to the host
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        return sock

    def _dtproto_connect(self, host, port):
        # DTProto connection setup (with multi-stage handshake and authentication)
        print(f"Connecting to DTProto proxy at {self.proxy_ip}:{self.proxy_port}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.proxy_ip, self.proxy_port))
        
        # Step 1: Send initial connection request
        handshake_message = f"CONNECT {host}:{port} DTPROTO/1.0\n"
        sock.sendall(handshake_message.encode())
        
        # Step 2: Receive connection confirmation or failure
        response = sock.recv(1024)
        if b"200 Connection established" not in response:
            raise ConnectionError("DTProto proxy connection failed at handshake step 1")
        
        print("Step 1: Handshake successful. Starting authentication...")

        # Step 3: Send authentication credentials with token validation
        auth_token = self._generate_auth_token()
        auth_message = f"AUTH {self.username} {self.password} {auth_token}\n"
        sock.sendall(auth_message.encode())
        
        # Step 4: Receive authentication response and validate token
        auth_response = sock.recv(1024)
        if b"200 Authentication successful" not in auth_response:
            raise ConnectionError("DTProto proxy authentication failed")
        
        print("Step 2: Authentication successful. Connection established.")

        return sock

    def _generate_auth_token(self):
        # Generate a real authentication token, for example using a hash of the password and a salt
        salt = os.urandom(16)
        token = hashlib.sha256(self.password.encode() + salt).hexdigest()
        return token
