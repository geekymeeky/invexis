import dns.resolver
import dns.message
import dns.flags
import dns.rcode


class DNSScanner:

    def __init__(self, domain):
        self.domain = domain
        self.ns = []
        self.mx = []
        self.txt = []
        self.srv = []
        self.spf = []
        self.dmarc = []
        self.dnssec = False
        self.ddos = dict()

    def scan(self):
        self._scan_ns()
        self._scan_mx()
        self._scan_txt()
        self._scan_srv()
        self._scan_dnssec()

        print(self.ns)

        return {
            'ns': self.ns,
            'mx': self.mx,
            'txt': self.txt,
            'srv': self.srv,
            'spf': self.spf,
            'dmarc': self.dmarc,
            'dnssec': self.dnssec,
            'ddos': self.ddos
        }

    def _scan_ns(self):
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

    def _scan_mx(self):
        try:
            mx_answers = dns.resolver.resolve(self.domain, 'MX')
            for mx_rdata in mx_answers:
                self.mx.append(str(mx_rdata.exchange).rstrip('.'))
        except:
            pass

    def _scan_txt(self):
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

    def _scan_srv(self):
        try:
            srv_answers = dns.resolver.resolve('_sip._tcp.' + self.domain,
                                               'SRV')
            for srv_rdata in srv_answers:
                self.srv.append(str(srv_rdata.target).rstrip('.'))
        except:
            pass

    def _scan_dnssec(self):
        try:
            query = dns.message.make_query(self.domain, 'DNSKEY')
            response = dns.query.udp(query, '8.8.8.8')
            if response.rcode() == dns.rcode.NOERROR:
                self.dnssec = True
        except:
            pass
