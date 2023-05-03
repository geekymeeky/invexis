import requests
from lib.shared.utils import exception
from lib.shared.scanner import Scanner


class SecurityHeaders(Scanner):
    """SecurityHeaders class to analyze security headers of a website
    """

    def __init__(self, target):
        super().__init__(target)
        headers = requests.head(f'{self.target}').headers
        self.headers = headers

    def scan(self):
        """Analyze security headers of a website

        Returns:
            dict: Analysis of security headers
        """
        analysis = {}
        analysis['X-XSS-Protection'] = self._check_xss_protection()
        analysis[
            'Content-Security-Policy'] = self._check_content_security_policy()
        analysis[
            'Strict-Transport-Security'] = self._check_strict_transport_security(
            )
        analysis['X-Frame-Options'] = self._check_x_frame_options()
        return analysis

    @exception()
    def _check_xss_protection(self):
        """Check if X-XSS-Protection header is set and enabled

        Returns:
            dict: Analysis of X-XSS-Protection header
        """
        xss_protection = self.headers.get('X-XSS-Protection')
        if xss_protection:
            return {'status': "enabled", 'policy': xss_protection}
        else:
            return {
                'status': "not set",
                'policy': 'not set',
                'solution':
                'Set X-XSS-Protection header with value "1; mode=block" to enable XSS protection in modern browsers',
                'severity': 'high'
            }

    @exception()
    def _check_content_security_policy(self):
        """Check if Content-Security-Policy header is set

        Returns:
            dict: Analysis of Content-Security-Policy header
        """
        content_security_policy = self.headers.get('Content-Security-Policy')
        if content_security_policy:
            return {
                'status': "enabled",
                'policy': content_security_policy,
            }
        else:
            return {
                'status': "not set",
                'policy': 'not set',
                'solution':
                'Set Content-Security-Policy header to specify allowed content sources and prevent XSS, clickjacking and other attacks',
                'severity': 'high'
            }

    @exception()
    def _check_strict_transport_security(self):
        """Check if Strict-Transport-Security header is set and has max-age of at least 1 year

        Returns:
            dict: Analysis of Strict-Transport-Security header
        """
        strict_transport_security = self.headers.get(
            'Strict-Transport-Security')
        if strict_transport_security:
            analysis = {
                'status': "enabled",
                'policy': strict_transport_security,
            }
            max_age = strict_transport_security.split('max-age=')[1].split(
                ';')[0]
            if int(max_age) < 31536000:
                analysis = {
                    'status': "enabled",
                    'policy': strict_transport_security,
                    'solution':
                    'Increase max-age to at least 31536000 seconds (1 year) to ensure long-term protection against protocol downgrade attacks',
                    'severity': 'medium'
                }
            return analysis
        else:
            return {
                'status': "not set",
                'policy': 'not set',
                'solution':
                'Set Strict-Transport-Security header to enable HTTPS-only mode and protect against protocol downgrade attacks',
                'severity': 'high'
            }

    @exception()
    def _check_x_frame_options(self):
        """Check if X-Frame-Options header is set and has value DENY or SAMEORIGIN

        Returns:
            dict: Analysis of X-Frame-Options header
        """
        x_frame_options = self.headers.get('X-Frame-Options')
        if x_frame_options:
            analysis = x_frame_options
            if x_frame_options != 'DENY' and x_frame_options != 'SAMEORIGIN':
                analysis = {
                    'status': x_frame_options,
                    'solution':
                    'Set X-Frame-Options header to DENY or SAMEORIGIN to prevent clickjacking attacks',
                    'severity': 'medium'
                }
            else:
                analysis = {
                    'status': 'enabled',
                    'policy': x_frame_options,
                }
            return analysis
        else:
            return {
                'status': 'not set',
                'solution':
                'Set X-Frame-Options header to DENY or SAMEORIGIN to prevent clickjacking attacks',
                'severity': 'high'
            }
