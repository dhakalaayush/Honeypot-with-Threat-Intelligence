import socket
import paramiko
import threading
import datetime
import ipaddress
from http.server import BaseHTTPRequestHandler, HTTPServer
from threat import check_ip_reputation
from database import init_db, log_attack

HOST_KEY = paramiko.RSAKey(filename='server.rsa') # Secure tunnel with the attacker

def process_and_log(ip, attack_type, data_captured):
    """Enriches public IPs with Threat Intelligence and stores records in SQLite."""
    threat_data = None
    try:
        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_private and not ip_obj.is_loopback:
            threat_data = check_ip_reputation(ip)
    except ValueError:
        pass

    log_attack(ip, attack_type, data_captured, threat_data)


# SSH

class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [SSH] attempt from {self.client_ip}")
        print(f"__Username: {username}")
        print(f"__Password: {password}\n")

        # Async logging and threat intelligence check
        captured_info = f"user={username} | pass={password}"
        threading.Thread(target=process_and_log, args=(self.client_ip, "SSH", captured_info)).start()

        return paramiko.AUTH_FAILED # The attacker is always rejected

    def get_allowed_auths(self, username):
        return 'password'

def handle_ssh_connection(client, addr):
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)
        server = SSHServer(addr[0])
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            return
        channel = transport.accept(20)
        if channel is None:
            transport.close()
    except Exception:
        pass

def start_ssh_honeypot(port=22):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(100)
        print(f"[*] SSH Honeypot listening on port {port}...")
        while True:
            client, addr = server_socket.accept()
            threading.Thread(target=handle_ssh_connection, args=(client, addr)).start()
    except PermissionError:
        print(f"[!] Error: Port {port} requires root/sudo privileges.")


# HTTP

class HTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass # Suppress default Python HTTP logging for a cleaner console

    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        # Capturing POST requests catches automated vulnerability scanners
        self.handle_request("POST")
        
    def handle_request(self, method):
        client_ip = self.client_address[0]
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        path = self.path
        user_agent = self.headers.get('User-Agent', 'Unknown')
        
        print(f"[{timestamp}] [HTTP] probe from {client_ip}")
        print(f"    Method: {method} | Path: {path}")
        print(f"    User-Agent: {user_agent}\n")
        
        # Async logging and threat intelligence check
        captured_info = f"method={method} | path={path} | ua={user_agent}"
        threading.Thread(target=process_and_log, args=(client_ip, "HTTP", captured_info)).start()
        
        # Present a fake admin login page to lure further interaction
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        html_payload = """
        <html>
            <head>
                <style>
                    *
                    {
                        font-family: arial, sans-serrif;
                    }

                    body
                    {
                        background: #b5f1ff;
                        padding: 30px;
                    }

                    h1
                    {
                        text-align: center;
                    }
                    
                    input
                    {
                        border: 0.5px solid black;
                        border-radius: 5px;
                        height: 30px;
                        width: 200px;
                        margin: 5px;
                    }

                </style>
            </head>
            <body>
                <h1>Blue Moon Corps</h1>
                <h2>Admin Login</h2>
                <p>Warning: Do not share. This page is for administrators only.</p>
                <form method='POST'>
                    Username: <input type='text' name='user'/><br>
                    Password: <input type='password' name='pass'/><br>
                    <input type='submit' value='Login'/>
                </form>
            </body>
        </html>
        """
        self.wfile.write(html_payload.encode('utf-8'))

def start_http_honeypot(port=80):
    try:
        server = HTTPServer(('0.0.0.0', port), HTTPHandler)
        print(f"[*] HTTP Honeypot listening on port {port}...")
        server.serve_forever()
    except PermissionError:
        print(f"[!] Error: Port {port} requires root/sudo privileges.")


if __name__ == "__main__":
    # Ensure database and table exist before accepting connections
    init_db()

    # Start the HTTP honeypot in a background thread
    http_thread = threading.Thread(target=start_http_honeypot, args=(80,))
    http_thread.daemon = True
    http_thread.start()
    
    # Start the SSH honeypot in the main thread
    start_ssh_honeypot(22)