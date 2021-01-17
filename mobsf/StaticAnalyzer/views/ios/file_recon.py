import io
import logging

from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import (
    MalwareDomainCheck,
)
from mobsf.StaticAnalyzer.views.shared_func import (
    url_n_email_extract,
)

logger = logging.getLogger(__name__)


def extract_urls_n_email(src, all_files, strings):
    """IPA URL and Email Extraction."""
    try:
        logger.info('Starting IPA URL and Email Extraction')
        email_n_file = []
        url_n_file = []
        url_list = []
        domains = {}
        all_files.append({'data': strings, 'name': 'IPA Strings Dump'})
        for file in all_files:
            if isinstance(file, dict):
                relative_src_path = file['name']
                dat = '\n'.join(file['data'])
            # Skip CodeResources and contents under Frameworks
            elif 'CodeResources' in file or '/Frameworks/' in file:
                continue
            elif file.endswith(('.nib', '.ttf', '.svg', '.woff2',
                                '.png', '.dylib', '.mobileprovision',
                                'Assets.car')):
                continue
            else:
                dat = ''
                relative_src_path = file.replace(src, '')
                with io.open(file,
                             mode='r',
                             encoding='utf8',
                             errors='ignore') as flip:
                    dat = flip.read()
            # Extract URLs and Emails from Plists
            urls, urls_nf, emails_nf = url_n_email_extract(
                dat, relative_src_path)
            url_list.extend(urls)
            url_n_file.extend(urls_nf)
            email_n_file.extend(emails_nf)
        # Unique URLs
        urls_list = list(set(url_list))
        # Domain Extraction and Malware Check
        logger.info('Performing Malware Check on extracted Domains')
        domains = MalwareDomainCheck().scan(urls_list)
        logger.info('Finished URL and Email Extraction')
        binary_recon = {
            'urls_list': urls_list,
            'urlnfile': url_n_file,
            'domains': domains,
            'emailnfile': email_n_file,
        }
        return binary_recon

    except Exception:
        logger.exception('IPA URL and Email Extraction')
