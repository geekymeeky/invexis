import dns.resolver
import dns.message
import dns.flags
import dns.rcode

dns.resolver.Cache.flush = lambda self: None


class DNSScanner:

    def getDomainFromHost(self, host):
        domain = host
        if domain.count('.') > 1:
            domain = domain[domain.find('.') + 1:]
        return domain

    def __init__(self, host):
        self.domain = self.getDomainFromHost(host)
        self.ns = []
        self.mx = []
        self.txt = []
        self.srv = []
        self.spf = []
        self.dmarc = []
        self.dnssec = False
        self.ddos = {}
        self.issues = []

    def scan(self):
        self._get_ns()
        self._get_mx()
        self._get_txt()
        self._get_srv()
        self._check_dnssec()
        self._check_dns_security()

        return {
            'ns': self.ns,
            'mx': self.mx,
            'txt': self.txt,
            'srv': self.srv,
            'spf': self.spf,
            'dmarc': self.dmarc,
            'dnssec': self.dnssec,
            'ddos': self.ddos,
            'issues': self.issues
        }

    def _get_ns(self):
        answers = dns.resolver.resolve(self.domain, 'NS')
        for rdata in answers:
            ns = str(rdata.target).rstrip('.')
            try:
                ns_answers = dns.resolver.resolve(ns, 'A')
                for ns_rdata in ns_answers:
                    self.ns.append(str(ns_rdata))
            except:
                pass

            try:
                ns_answers = dns.resolver.resolve(ns, 'AAAA')
                for ns_rdata in ns_answers:
                    self.ns.append(str(ns_rdata))
            except:
                pass

    def _get_mx(self):
        try:
            mx_answers = dns.resolver.resolve(self.domain, 'MX')
            for mx_rdata in mx_answers:
                self.mx.append(str(mx_rdata.exchange).rstrip('.'))
        except:
            pass

    def _get_txt(self):
        try:
            txt_answers = dns.resolver.resolve(self.domain, 'TXT')
            for txt_rdata in txt_answers:
                txt_record = str(txt_rdata).replace('"', '')
                if txt_record.startswith('v=spf1'):
                    self.spf.append(txt_record)
                elif txt_record.startswith('v=DMARC1'):
                    self.dmarc.append(txt_record)
                else:
                    self.txt.append(txt_record)
        except:
            pass

    def _get_srv(self):
        try:
            srv_answers = dns.resolver.resolve(f'_sip._tcp.{self.domain}', 'SRV')
            for srv_rdata in srv_answers:
                self.srv.append(str(srv_rdata.target).rstrip('.'))
        except:
            pass

    def _check_dnssec(self):
        #  If the DNS records are not in the same subset, it can be easier for an attacker to spoof DNS packets and redirect traffic
        try:
            query = dns.message.make_query(self.domain, 'DNSKEY')
            response = dns.query.udp(query, '8.8.8.8')
            if response.rcode() == dns.rcode.NOERROR:
                self.dnssec = True
        except:
            pass

    def _is_same_subnet(self, ip1, ip2):
        ip1 = ip1.split('.')
        ip2 = ip2.split('.')
        return ip1[0] == ip2[0] and ip1[1] == ip2[1] and ip1[2] == ip2[2]

    def _check_dns_security(self):

        # check dnssec
        if not self.dnssec:
            self.issues.append({
                'title': 'DNSSEC is not enabled',
                'description':
                'DNSSEC is important because it protects against attacks where DNS data is modified in transit. It also provides a means for a resolver to validate that the information it receives has not been tampered with.',
                'recommendation': 'Enable DNSSEC',
                'severity': 'high',
                'reason': 'Protects against DNS spoofing'
            })

        # check if all NS records are in the same subnet
        if len(self.ns) > 1:
            for ns in self.ns:
                if not self._is_same_subnet(ns, self.ns[0]):
                    self.issues.append({
                        'title':
                        'NS records are not in the same subnet',
                        'description':
                        'NS records are not in the same subnet',
                        'recommendation':
                        'NS records should be in the same subnet',
                        'severity':
                        'high',
                        'reason':
                        'Protects against DNS spoofing and DDoS attacks (DNS amplification)'
                    })
                    break

        #check spf record
        if len(self.spf) == 0:
            self.issues.append({
                'title': 'SPF record is not set',
                'description': 'SPF record is not set',
                'recommendation': 'Set SPF record',
                'severity': 'high',
                'reason': 'Protects against email spoofing'
            })

        #check dmarc record
        if len(self.dmarc) == 0:
            self.issues.append({
                'title': 'DMARC record is not set',
                'description': 'DMARC record is not set',
                'recommendation': 'Set DMARC record',
                'severity': 'high',
                'reason': 'Protects against email spoofing'
            })
