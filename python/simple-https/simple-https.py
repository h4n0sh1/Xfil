## Credits to Martin Pitt for original source from 01/01/2026 : https://piware.de/2011/01/creating-an-https-server-in-python/
## Modified with copilot to use temporary certificate files for demonstration purposes

from http.server import HTTPServer, SimpleHTTPRequestHandler
import logging
import ssl
from pathlib import Path
import subprocess
import sys
import re
import time

class CustomHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        logging.info("%s - - [%s] %s", self.client_address[0], self.log_date_time_string(), format % args)

    def do_POST(self):
        data_dir = Path(__file__).resolve().parent / "data"
        data_dir.mkdir(exist_ok=True)

        content_type = self.headers.get('Content-Type', '')
        content_length = int(self.headers.get('Content-Length', 0))
        if content_type.startswith('multipart/form-data'):
            # Extract boundary from content_type
            match = re.search(r'boundary=(.*)', content_type)
            if not match:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing boundary in multipart/form-data")
                return
            boundary = match.group(1)
            if boundary.startswith('"') and boundary.endswith('"'):
                boundary = boundary[1:-1]
            boundary = boundary.encode()
            post_data = self.rfile.read(content_length)
            # Split parts
            parts = post_data.split(b'--' + boundary)
            filename = None
            file_data = None
            for part in parts:
                if not part or part == b'--\r\n' or part == b'--':
                    continue
                headers, _, body = part.partition(b'\r\n\r\n')
                if not headers or not body:
                    continue
                headers_str = headers.decode(errors='ignore')
                disposition_match = re.search(r'Content-Disposition:.*name="[^"]*"; filename="([^"]+)"', headers_str)
                if disposition_match:
                    filename = disposition_match.group(1)
                    # Remove trailing boundary markers and CRLF
                    body = body.rstrip(b'\r\n')
                    file_data = body
                    break
            if not filename:
                filename = f"upload_{self.client_address[0].replace('.', '_')}_{int(time.time())}"
            if file_data is None:
                file_data = b''
        else:
            # Not multipart: treat as raw upload
            file_data = self.rfile.read(content_length) if content_length > 0 else b''
            filename = f"upload_{self.client_address[0].replace('.', '_')}_{int(time.time())}"

        file_path = data_dir / filename
        try:
            with open(file_path, "wb") as f:
                f.write(file_data)
            logging.info(f"Saved uploaded file to {file_path}")
            self.send_response(201)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"File saved as {file_path.name}".encode())
        except Exception as e:
            logging.error(f"Failed to save file: {e}")
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"File upload failed")


def generate_self_signed_cert(cert_path: Path, key_path: Path) -> None:
    """Generate a self-signed cert and key.

    Tries the `cryptography` library first, falls back to `openssl` command.
    """
    def _do_crypto_generate():
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import ipaddress
        from datetime import datetime, timedelta, timezone

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])

        san = x509.SubjectAlternativeName([
            x509.DNSName(u"localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )

        key_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_bytes = cert.public_bytes(serialization.Encoding.PEM)

        key_path.write_bytes(key_bytes)
        cert_path.write_bytes(cert_bytes)

    # Try generating with cryptography; if missing, attempt to install then retry
    try:
        _do_crypto_generate()
        return
    except Exception:
        try:
            print("'cryptography' package not found — attempting to install via pip...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
            _do_crypto_generate()
            return
        except Exception:
            pass

    # Fallback to openssl command if available
    try:
        subprocess.check_call([
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_path),
            "-x509",
            "-days",
            "3650",
            "-out",
            str(cert_path),
            "-subj",
            "/CN=localhost",
        ])
        return
    except Exception:
        raise RuntimeError(
            "Unable to generate certificate: install the 'cryptography' package or ensure 'openssl' is in PATH."
        )


HERE = Path(__file__).resolve().parent
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
CERT_FILE = HERE / "cert.pem"
KEY_FILE = HERE / "key.pem"

if not CERT_FILE.exists() or not KEY_FILE.exists():
    print(f"Generating self-signed certificate and key at {CERT_FILE} and {KEY_FILE}")
    try:
        generate_self_signed_cert(CERT_FILE, KEY_FILE)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
context.check_hostname = False
# Skip certificate verification
context.verify_mode = ssl.CERT_NONE

# Dynamically detect the main ethernet interface IP
import socket
def get_main_ip():
    try:
        # This does not actually connect, just figures out the outbound interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

SERVER_IP = get_main_ip()

with HTTPServer((SERVER_IP, 443), CustomHandler) as httpd:
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    logging.info(f"Serving HTTPS on https://{SERVER_IP}:443/")
    httpd.serve_forever()