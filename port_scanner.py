
import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

PORT_INFO = {
    20: ("FTP Data", "Transfers file data.", "Prefer secure file-transfer methods."),
    21: ("FTP", "Controls file-transfer sessions.", "Plain FTP may expose credentials."),
    22: ("SSH", "Encrypted remote login and command access.", "Restrict access and use strong authentication."),
    23: ("Telnet", "Legacy remote terminal access.", "Telnet traffic is unencrypted."),
    25: ("SMTP", "Transfers email between mail servers.", "Review mail-server configuration."),
    53: ("DNS", "Resolves domain names to IP addresses.", "Allow only intended DNS access."),
    80: ("HTTP", "Serves regular, unencrypted web traffic.", "Use HTTPS for sensitive traffic."),
    110: ("POP3", "Retrieves email from a mail server.", "Prefer encrypted email access."),
    123: ("NTP", "Synchronizes system clocks.", "Restrict access to intended networks."),
    135: ("MS RPC", "Supports Windows Remote Procedure Call services.", "Restrict exposure to trusted networks."),
    139: ("NetBIOS", "Supports legacy Windows file and printer sharing.", "Review whether legacy sharing is needed."),
    143: ("IMAP", "Accesses and manages email on a server.", "Prefer encrypted email access."),
    161: ("SNMP", "Monitors and manages network devices.", "Use secure settings and restrict access."),
    389: ("LDAP", "Queries directory services.", "Protect directory traffic and restrict access."),
    443: ("HTTPS", "Serves encrypted web traffic.", "Maintain TLS and web-server security."),
    445: ("SMB", "Windows file and printer sharing.", "Avoid exposing SMB to untrusted networks."),
    465: ("SMTPS", "Transfers email using implicit TLS.", "Check TLS and authentication settings."),
    587: ("SMTP Submission", "Allows clients to send outgoing email.", "Require authentication and encryption."),
    993: ("IMAPS", "Accesses email over encrypted IMAP.", "Maintain TLS and account security."),
    995: ("POP3S", "Retrieves email over encrypted POP3.", "Maintain TLS and account security."),
    1433: ("MS SQL Server", "Database connections to Microsoft SQL Server.", "Restrict access to trusted systems."),
    1521: ("Oracle DB", "Common Oracle Database listener port.", "Avoid broad database exposure."),
    3306: ("MySQL", "Connections to a MySQL database.", "Restrict access to trusted systems."),
    3389: ("RDP", "Remote Desktop access to Windows.", "Use strong authentication and network controls."),
    5432: ("PostgreSQL", "Connections to a PostgreSQL database.", "Restrict access to trusted application hosts."),
    5900: ("VNC", "Remote graphical desktop access.", "Restrict access and use secure connections."),
    6379: ("Redis", "Connections to a Redis data store.", "Do not expose an unprotected datastore."),
    8080: ("HTTP Alternate", "Often used by web applications and proxies.", "Confirm the application and its access controls."),
    8443: ("HTTPS Alternate", "Often used for alternate HTTPS services.", "Check access controls and TLS.")
}


def normalize_host(target):
    target = target.strip()
    parsed = urlparse(target if "://" in target else "//" + target)
    return parsed.hostname or ""


def check_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.35)

    try:
        if sock.connect_ex((ip, port)) == 0:
            return port
    except OSError:
        pass
    finally:
        sock.close()

    return None


def scan_ports(target):
    host = normalize_host(target)

    if not host:
        return None, []

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return None, []

    # Scan only systems you own or have permission to test.
    with ThreadPoolExecutor(max_workers=64) as executor:
        results = executor.map(
            lambda port: check_port(ip, port),
            range(1, 1025)
        )

    open_ports = [port for port in results if port is not None]
    return ip, open_ports


def get_port_info(port):
    info = PORT_INFO.get(
        port,
        (
            "Unknown / Other Service",
            "No common purpose is listed for this port.",
            "Verify the actual service before drawing conclusions."
        )
    )

    return {
        "port": port,
        "service": info[0],
        "purpose": info[1],
        "note": info[2]
    }


if __name__ == "__main__":
    target = "127.0.0.1"
    ip, ports = scan_ports(target)

    print("Target:", target)
    print("IP:", ip)

    for port in ports:
        print(get_port_info(port))