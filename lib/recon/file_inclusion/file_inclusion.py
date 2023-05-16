import requests
from lib.shared.scanner import Scanner
from urllib3.util.url import parse_url


class FileInclusionScanner(Scanner):
    with open("lib/recon/file_inclusion/payloads.txt", "r") as f:
        PAYLOADS = f.read().splitlines()

    def __init__(self, target):
        self.target = target
        self.results = {}
        self.url = parse_url(target)

    def scan(self):
        for payload in self.PAYLOADS:
            print(f"Scanning {self.url.host}{payload}")
            url = f"{self.url.scheme}://{self.url.host}/{payload}"
            response = requests.get(url)
            if response:
                self.results[url] = {
                    "status_code": response.status_code,
                    "content": response.text,
                    "payload": payload,
                    "analysis": "File Inclusion Vulnerability Found!"
                }

        return self.results
    
    def __repr__(self):
        return f"<FileInclusionScanner target={self.target}>"
    
    