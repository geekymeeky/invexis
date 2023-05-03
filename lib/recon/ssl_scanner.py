import socket
import ssl
from urllib3.util import url
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime

from lib.constants.ssl_constants import EXPIRED
from lib.shared.scanner import Scanner


class SSLScanner(Scanner):

    def __init__(self, target):
        super().__init__(target)
        self.host = url.parse_url(target).host
        self.port = 443
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE
        self.analysis = {}

    def scan(self):
        """Scan the target for SSL/TLS information.

        Returns:
            dict: A dictionary containing the SSL/TLS information.
        """
        try:
            with socket.create_connection((self.host, self.port)) as sock:
                with self.context.wrap_socket(
                        sock, server_hostname=self.host) as ssock:
                    data = ssock.getpeercert(True)
                    pem_data = ssl.DER_cert_to_PEM_cert(data)
                    cert_data = x509.load_pem_x509_certificate(
                        str.encode(pem_data))

                    self._check_expired(cert_data)
                    self._check_self_signed(cert_data)
                    self._check_wrong_host(cert_data)

                    return {
                        "ssl_version":
                        ssock.version(),
                        "issuer_name":
                        cert_data.issuer.rfc4514_string(),
                        "subject_name":
                        cert_data.subject.rfc4514_string(),
                        "not_before":
                        cert_data.not_valid_before.isoformat(),
                        "not_after":
                        cert_data.not_valid_after.isoformat(),
                        "algorithm":
                        cert_data.signature_hash_algorithm.name,
                        "serial_number":
                        cert_data.serial_number,
                        "version":
                        cert_data.version.name,
                        "public_key":
                        cert_data.public_key().public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.
                            SubjectPublicKeyInfo).decode(),
                        "fingerprint":
                        cert_data.fingerprint(hashes.SHA256()).hex(),
                        "signature":
                        cert_data.signature.hex(),
                        "analysis":
                        self.analysis,
                    }

        except ssl.CertificateError as e:
            return {"error": "CertificateError", "message": e.verify_message}

        except ssl.SSLError as e:
            return {"error": "SSLError", "message": e.reason}

    def _check_expired(self, cert_obj: x509.Certificate):
        if cert_obj.not_valid_after < datetime.now():
            self.analysis["expired"] = EXPIRED[True]
        else:
            self.analysis["expired"] = EXPIRED[False]

    def _check_self_signed(self, cert_obj: x509.Certificate):
        if cert_obj.issuer.rfc4514_string() == cert_obj.subject.rfc4514_string(
        ):
            self.analysis["self_signed"] = {
                "error": "Self Signed",
                "message": "The certificate is self signed."
            }
        else:
            self.analysis["self_signed"] = {
                "error": False,
                "message": "The certificate is signed by a trusted CA."
            }

    def _check_wrong_host(self, cert_obj: x509.Certificate):
        subject = cert_obj.subject.rfc4514_string()
        if self.host in subject:
            self.analysis["wrong_host"] = {
                "error": False,
                "message": "The certificate is valid for the host."
            }
        else:
            self.analysis["wrong_host"] = {
                "error":
                "Wrong Host",
                "message":
                "The certificate is not valid for the host. Consider using a certificate for the host."
            }

    def __repr__(self):
        return f"SSLScanner(host={self.host}, port={self.port})"
