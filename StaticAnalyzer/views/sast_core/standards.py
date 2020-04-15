# -*- coding: utf_8 -*-
"""Standards Supported by MobSF."""


# OWASP Mobile Top 10 Risk 2016
# https://owasp.org/www-project-mobile-top-10/
OWASP = {
    'm1': 'M1: Improper Platform Usage',
    'm2': 'M2: Insecure Data Storage',
    'm3': 'M3: Insecure Communication',
    'm4': 'M4: Insecure Authentication',
    'm5': 'M5: Insufficient Cryptography',
    'm6': 'M6: Insecure Authorization',
    'm7': 'M7: Client Code Quality',
    'm8': 'M8: Code Tampering',
    'm9': 'M9: Reverse Engineering',
    'm10': 'M10: Extraneous Functionality',
}

# OWASP Mobile AppSec Verification Standard (MAVS)
# https://mobile-security.gitbook.io/masvs/security-requirements/
OWASP_MSTG = {
    # Architecture, Design and Threat Modeling Requirements
    'arch-1': 'MSTG-ARCH-1',
    'arch-2': 'MSTG-ARCH-2',
    'arch-3': 'MSTG-ARCH-3',
    'arch-4': 'MSTG-ARCH-4',
    'arch-5': 'MSTG-ARCH-5',
    'arch-6': 'MSTG-ARCH-6',
    'arch-7': 'MSTG-ARCH-7',
    'arch-8': 'MSTG-ARCH-8',
    'arch-9': 'MSTG-ARCH-9',
    'arch-10': 'MSTG-ARCH-10',
    'arch-11': 'MSTG-ARCH-11',
    'arch-12': 'MSTG-ARCH-12',
    # Data Storage and Privacy Requirements
    'storage-1': 'MSTG-STORAGE-1',
    'storage-2': 'MSTG-STORAGE-2',
    'storage-3': 'MSTG-STORAGE-3',
    'storage-4': 'MSTG-STORAGE-4',
    'storage-5': 'MSTG-STORAGE-5',
    'storage-6': 'MSTG-STORAGE-6',
    'storage-7': 'MSTG-STORAGE-7',
    'storage-8': 'MSTG-STORAGE-8',
    'storage-9': 'MSTG-STORAGE-9',
    'storage-10': 'MSTG-STORAGE-10',
    'storage-11': 'MSTG-STORAGE-11',
    'storage-12': 'MSTG-STORAGE-12',
    'storage-13': 'MSTG-STORAGE-13',
    'storage-14': 'MSTG-STORAGE-14',
    'storage-15': 'MSTG-STORAGE-15',
    # Cryptography Requirements
    'crypto-1': 'MSTG-CRYPTO-1',
    'crypto-2': 'MSTG-CRYPTO-2',
    'crypto-3': 'MSTG-CRYPTO-3',
    'crypto-4': 'MSTG-CRYPTO-4',
    'crypto-5': 'MSTG-CRYPTO-5',
    'crypto-6': 'MSTG-CRYPTO-6',
    # Authentication and Session Management Requirements
    'auth-1': 'MSTG-AUTH-1',
    'auth-2': 'MSTG-AUTH-2',
    'auth-3': 'MSTG-AUTH-3',
    'auth-4': 'MSTG-AUTH-4',
    'auth-5': 'MSTG-AUTH-5',
    'auth-6': 'MSTG-AUTH-6',
    'auth-7': 'MSTG-AUTH-7',
    'auth-8': 'MSTG-AUTH-8',
    'auth-9': 'MSTG-AUTH-9',
    'auth-10': 'MSTG-AUTH-10',
    'auth-11': 'MSTG-AUTH-11',
    'auth-12': 'MSTG-AUTH-12',
    # Network Communication Requirements
    'network-1': 'MSTG-NETWORK-1',
    'network-2': 'MSTG-NETWORK-2',
    'network-3': 'MSTG-NETWORK-3',
    'network-4': 'MSTG-NETWORK-4',
    'network-5': 'MSTG-NETWORK-5',
    'network-6': 'MSTG-NETWORK-6',
    # Platform Interaction Requirements
    'platform-1': 'MSTG-PLATFORM-1',
    'platform-2': 'MSTG-PLATFORM-2',
    'platform-3': 'MSTG-PLATFORM-3',
    'platform-4': 'MSTG-PLATFORM-4',
    'platform-5': 'MSTG-PLATFORM-5',
    'platform-6': 'MSTG-PLATFORM-6',
    'platform-7': 'MSTG-PLATFORM-7',
    'platform-8': 'MSTG-PLATFORM-8',
    'platform-9': 'MSTG-PLATFORM-9',
    'platform-10': 'MSTG-PLATFORM-10',
    'platform-11': 'MSTG-PLATFORM-11',
    # Code Quality and Build Setting Requirements
    'code-1': 'MSTG-CODE-1',
    'code-2': 'MSTG-CODE-2',
    'code-3': 'MSTG-CODE-3',
    'code-4': 'MSTG-CODE-4',
    'code-5': 'MSTG-CODE-5',
    'code-6': 'MSTG-CODE-6',
    'code-7': 'MSTG-CODE-7',
    'code-8': 'MSTG-CODE-8',
    'code-9': 'MSTG-CODE-9',
    # Resilience Requirements
    'resilience-1': 'MSTG-RESILIENCE-1',
    'resilience-2': 'MSTG-RESILIENCE-2',
    'resilience-3': 'MSTG-RESILIENCE-3',
    'resilience-4': 'MSTG-RESILIENCE-4',
    'resilience-5': 'MSTG-RESILIENCE-5',
    'resilience-6': 'MSTG-RESILIENCE-6',
    'resilience-7': 'MSTG-RESILIENCE-7',
    'resilience-8': 'MSTG-RESILIENCE-8',
    'resilience-9': 'MSTG-RESILIENCE-9',
    'resilience-10': 'MSTG-RESILIENCE-10',
    'resilience-11': 'MSTG-RESILIENCE-11',
    'resilience-12': 'MSTG-RESILIENCE-12',
    'resilience-13': 'MSTG-RESILIENCE-13',
}

# Common Weakness Enumeration (CWE)
# https://cwe.mitre.org/data/index.html
CWE = {
    'CWE-22': ('CWE-22 - Improper Limitation of a Pathname'
               ' to a Restricted Directory (\'Path Traversal\')'),
    'CWE-89': ('CWE-89 - Improper Neutralization of Special '
               'Elements used in an SQL Command (\'SQL Injection\')'),
    'CWE-95': ('CWE-95 - Improper Neutralization of Directives'
               ' in Dynamically Evaluated Code (\'Eval Injection\')'),
    'CWE-119': ('CWE-119 - Improper Restriction of Operations '
                'within the Bounds of a Memory Buffer'),
    'CWE-200': ('CWE-200 - Exposure of Sensitive Information'
                ' to an Unauthorized Actor'),
    'CWE-250': 'CWE-250 - Execution with Unnecessary Privileges',
    'CWE-276': 'CWE-276 - Incorrect Default Permissions',
    'CWE-295': 'CWE-295 - Improper Certificate Validation',
    'CWE-757': ('CWE-757 - Selection of Less-Secure Algorithm '
                'During Negotiation (\'Algorithm Downgrade\')'),
    'CWE-311': 'CWE-311 - Missing Encryption of Sensitive Data',
    'CWE-312': 'CWE-312 - Cleartext Storage of Sensitive Information',
    'CWE-327': 'CWE-327 - Use of a Broken or Risky Cryptographic Algorithm',
    'CWE-329': 'CWE-329 - Not Using a Random IV with CBC Mode',
    'CWE-330': 'CWE-330 - Use of Insufficiently Random Values',
    'CWE-502': 'CWE-502 - Deserialization of Untrusted Data',
    'CWE-532': 'CWE-532 - Insertion of Sensitive Information into Log File',
    'CWE-676': 'CWE-676 - Use of Potentially Dangerous Function',
    'CWE-749': 'CWE-749 - Exposed Dangerous Method or Function',
    'CWE-780': 'CWE-780 - Use of RSA Algorithm without OAEP',
    'CWE-789': 'CWE-789 - Uncontrolled Memory Allocation',
    'CWE-919': 'CWE-919 - Weaknesses in Mobile Applications',
    'CWE-939': ('CWE-939 - Improper Authorization in Handler for'
                ' Custom URL Scheme'),
}
