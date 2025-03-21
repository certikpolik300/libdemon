import socket
import threading

# Function to handle client requests
def handle_client(client_socket):
    request = client_socket.recv(1024)
    print(f"Received request: {request.decode('utf-8')}")
    
    # Send a simple response back to the client
    response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello from proxy server!"
    client_socket.sendall(response.encode('utf-8'))
    
    # Close the connection
    client_socket.close()

# Function to start the proxy server
def start_proxy_server():
    # Define the server address and port
    server_address = ('0.0.0.0', 53149)

    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the server socket to the address and port
    server_socket.bind(server_address)

    # Listen for incoming connections
    server_socket.listen(5)
    print(f"Proxy server listening on {server_address[0]}:{server_address[1]}...")

    # Accept connections in a loop
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection received from {client_address}")
        
        # Handle the client in a new thread
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_proxy_server()
