import json
from lib.shared.scanner import Scanner
from urllib3.util.url import parse_url
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
import requests
import time
from concurrent.futures import ThreadPoolExecutor


def host(url):
    return parse_url(url).host


class CorsMisconfigScanner(Scanner):

    disable_warnings(InsecureRequestWarning)

    header_dict = {
        'User-Agent':
        'Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0',
        'Accept':
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip',
        'DNT': '1',
        'Connection': 'close',
    }

    with open('lib/recon/cors_misconfig/details.json', 'r') as f:
        details = json.load(f)

    def __init__(self, target):
        super().__init__(target)
        self.target = target
        self.parsed = parse_url(target)
        self.root = host(target)
        self.netloc = self.parsed.netloc
        self.scheme = self.parsed.scheme

        self.url = self.scheme + "://" + self.netloc + (self.parsed.path
                                                        or '/')

        self.delay = 0.5
        self.results = {}

    def scan(self):
        threadpool = ThreadPoolExecutor(max_workers=2)
        future = threadpool.submit(self.cors)
        result = future.result()
        if result:
            self.results.update(result)
            return self.results[self.url]
        else:
            return {
                'status': 'not vulnerable',
                'details': 'No CORS misconfiguration found'
            }

    def cors(self):
        try:
            return self.active_tests(self.url, self.root, self.scheme,
                                     self.header_dict, self.delay)
        except ConnectionError as exc:
            print("Connection error: ", exc)

    def active_tests(self, url, root, scheme, header_dict, delay):
        origin = scheme + '://' + root
        headers = self._requester(url, scheme, header_dict, origin)
        acao_header, acac_header = headers.get(
            'access-control-allow-origin',
            None), headers.get('access-control-allow-credentials', None)
        if acao_header is None:
            return

        origin = scheme + '://' + 'example.com'
        headers = self._requester(url, scheme, header_dict, origin)
        acao_header, acac_header = headers.get(
            'access-control-allow-origin',
            None), headers.get('access-control-allow-credentials', None)
        if acao_header and acao_header == (origin):
            info = self.details['origin reflected']
            info['acao header'] = acao_header
            info['acac header'] = acac_header
            return {url: info}
        time.sleep(delay)

        origin = scheme + '://' + root + '.example.com'
        headers = self._requester(url, scheme, header_dict, origin)
        acao_header, acac_header = headers.get(
            'access-control-allow-origin',
            None), headers.get('access-control-allow-credentials', None)
        if acao_header and acao_header == (origin):
            info = self.details['post-domain wildcard']
            info['acao header'] = acao_header
            info['acac header'] = acac_header
            return {url: info}
        time.sleep(delay)

        origin = scheme + '://d3v' + root
        headers = self._requester(url, scheme, header_dict, origin)
        acao_header, acac_header = headers.get(
            'access-control-allow-origin',
            None), headers.get('access-control-allow-credentials', None)
        if acao_header and acao_header == (origin):
            info = self.details['pre-domain wildcard']
            info['acao header'] = acao_header
            info['acac header'] = acac_header
            return {url: info}
        time.sleep(delay)

        origin = 'null'
        headers = self._requester(url, '', header_dict, origin)
        acao_header, acac_header = headers.get(
            'access-control-allow-origin',
            None), headers.get('access-control-allow-credentials', None)
        if acao_header and acao_header == 'null':
            info = self.details['null origin allowed']
            info['acao header'] = acao_header
            info['acac header'] = acac_header
            return {url: info}
        time.sleep(delay)

        origin = scheme + '://' + root + '_.example.com'
        headers = self._requester(url, scheme, header_dict, origin)
        acao_header, acac_header = headers.get(
            'access-control-allow-origin',
            None), headers.get('access-control-allow-credentials', None)
        if acao_header and acao_header == origin:
            info = self.details['unrecognized underscore']
            info['acao header'] = acao_header
            info['acac header'] = acac_header
            return {url: info}
        time.sleep(delay)

        origin = scheme + '://' + root + '%60.example.com'
        headers = self._requester(url, scheme, header_dict, origin)
        acao_header, acac_header = headers.get(
            'access-control-allow-origin',
            None), headers.get('access-control-allow-credentials', None)
        if acao_header and '`.example.com' in acao_header:
            info = self.details['broken parser']
            info['acao header'] = acao_header
            info['acac header'] = acac_header
            return {url: info}
        time.sleep(delay)

        if root.count('.') > 1:
            origin = scheme + '://' + root.replace('.', 'x', 1)
            headers = self._requester(url, scheme, header_dict, origin)
            acao_header, acac_header = headers.get(
                'access-control-allow-origin',
                None), headers.get('access-control-allow-credentials', None)
            if acao_header and acao_header == origin:
                info = self.details['unescaped regex']
                info['acao header'] = acao_header
                info['acac header'] = acac_header
                return {url: info}
            time.sleep(delay)
        origin = 'http://' + root
        headers = self._requester(url, 'http', header_dict, origin)
        acao_header, acac_header = headers.get(
            'access-control-allow-origin',
            None), headers.get('access-control-allow-credentials', None)
        if acao_header and acao_header.startswith('http://'):
            info = self.details['http origin allowed']
            info['acao header'] = acao_header
            info['acac header'] = acac_header
            return {url: info}
        else:
            return self.passive_tests(url, headers)

    def passive_tests(self, url, headers):
        root = host(url)
        acao_header, acac_header = headers.get(
            'access-control-allow-origin',
            None), headers.get('access-control-allow-credentials', None)
        if acao_header == '*':
            info = self.details['wildcard value']
            info['acao header'] = acao_header
            info['acac header'] = acac_header
            return {url: info}
        if root:
            if host(acao_header) and root != host(acao_header):
                info = self.details['third party allowed']
                info['acao header'] = acao_header
                info['acac header'] = acac_header
                return {url: info}

    def _requester(self, url, scheme, headers, origin):
        headers['Origin'] = origin
        try:
            response = requests.get(url, headers=headers, verify=False)
            headers = response.headers
            for key, value in headers.items():
                if key.lower() == 'access-control-allow-origin':
                    return headers
        except requests.exceptions.RequestException as e:
            if 'Failed to establish a new connection' in str(e):
                print('Failed to establish a new connection')
            elif 'requests.exceptions.TooManyRedirects:' in str(e):
                print('Too many redirects')
        return {}
