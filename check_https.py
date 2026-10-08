import socket
import ssl

host = "172.20.83.128"
port = 443

context = ssl.create_default_context()

try:
    with socket.create_connection((host, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=host) as secure_sock:
            print("HTTPS connection successful")
            print("TLS version:", secure_sock.version())
            print("Cipher:", secure_sock.cipher()[0])

except Exception as e:
    print("Connection failed:", e)