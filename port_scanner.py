import socket
from concurrent.futures import ThreadPoolExecutor


def check_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)

    try:
        result = sock.connect_ex((ip, port))

        if result == 0:
            return port

    except socket.error:
        pass

    finally:
        sock.close()

    return None


def scan_ports(host):

    open_ports = []

    # Resolve hostname
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return None, []

    # Scan ports 1-1024 using multiple workers
    with ThreadPoolExecutor(max_workers=100) as executor:

        results = executor.map(
            lambda port: check_port(ip, port),
            range(1, 1025)
        )

    for port in results:

        if port is not None:
            open_ports.append(port)

    return ip, open_ports


# Test scanner directly
if __name__ == "__main__":

    host = "172.20.83.243"

    ip, open_ports = scan_ports(host)

    if ip is None:
        print("Could not resolve the hostname.")

    else:
        print(f"Target: {host}")
        print(f"IP address: {ip}")

        print("\nOpen ports:")

        for port in open_ports:
            print(f"[OPEN] Port {port}")

        print("\nScan completed.")