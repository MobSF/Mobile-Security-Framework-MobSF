import logging


logger = logging.getLogger(__name__)


def check_transport_security(p_list):
    """Check info.plist for insecure connection configurations."""
    logger.info('Checking for Insecure Connections')
    ats = []
    if 'NSAppTransportSecurity' in p_list:
        ats_dict = p_list['NSAppTransportSecurity']
        if ats_dict.get('NSAllowsArbitraryLoads'):
            ats.append({
                'issue': 'App Transport Security is allowed',
                'status': 'insecure',
                'description': (
                    'App Transport Security restrictions are disabled'
                    ' for all network connections. Disabling ATS means that '
                    'unsecured HTTP connections are allowed. HTTPS '
                    'connections are also allowed, and are still subject'
                    ' to default server trust evaluation. However, '
                    'extended security checks like requiring a minimum '
                    'Transport Layer Security (TLS) protocol version—are'
                    ' disabled. This setting is not applicable to domains '
                    'listed in NSExceptionDomains.'),
            })
        if ats_dict.get('NSAllowsArbitraryLoadsForMedia'):
            ats.append({
                'issue': 'Insecure media load is allowed',
                'status': 'insecure',
                'description': (
                    'App Transport Security restrictions are disabled for '
                    'media loaded using the AVFoundation framework, '
                    'without affecting your URLSession connections.'
                    ' This setting is not applicable to domains '
                    'listed in NSExceptionDomains.'),
            })
        if ats_dict.get('NSAllowsArbitraryLoadsInWebContent'):
            ats.append({
                'issue': 'Insecure WebView load is allowed',
                'status': 'insecure',
                'description': (
                    'App Transport Security restrictions are disabled for'
                    ' requests made from WebViews without affecting your'
                    ' URLSession connections. This setting is not applicable'
                    ' to domains listed in NSExceptionDomains.'),
            })
        exception_domain = ats_dict.get('NSExceptionDomains')
        if exception_domain:
            domain_exp = 'NSTemporaryExceptionAllowsInsecureHTTPLoads'
            for domain, config in exception_domain.items():
                if isinstance(config, dict) and config.get(domain_exp):
                    findings = {
                        'issue': ('Insecure communication'
                                  ' to {} is allowed'.format(domain)),
                        'status': 'insecure',
                        'description': (
                            'This settings allow insecure HTTP loads for {},'
                            ' or to be able to loosen the server trust '
                            'evaluation requirements for HTTPS '
                            'connections to the domain. '.format(domain)),
                    }
                    if config.get('NSIncludesSubdomains'):
                        findings['description'] += (
                            'This settings is applicable to the'
                            ' subdomains as well. '
                        )
                    if config.get('NSExceptionMinimumTLSVersion'):
                        findings['description'] += (
                            'Minimum TLS '
                            'Version: {}'.format(
                                config.get(
                                    'NSTemporaryExceptionMinimumTLSVersion'))
                        )
                    ats.append(findings)
    return ats
