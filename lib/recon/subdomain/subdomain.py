import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.util import parse_url

with open('lib/recon/subdomain/subdomains.txt', 'r') as f:
    subdomains = f.read().splitlines()


class SubdomainEnum:
    analysis = []

    def __init__(self, target):
        self.target = parse_url(target)
        self.subdomains = subdomains

    def _verifyIfExist(self, url):
        try:
            req = requests.get(url)
            if req.status_code == 200:
                self.analysis.append(url)
                print(url)
                return True
            else:
                return False
        except Exception as e:
            pass

    def run(self):
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(self._verifyIfExist,
                                f'http://{subdomain}.{self.target.host}')
                for subdomain in self.subdomains
            ]
            for future in as_completed(futures):
                if future.result():
                    print(future.result())

        return self.analysis
