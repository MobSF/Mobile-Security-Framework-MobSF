"""Create a new group and add permissions to it."""
from django.contrib.auth.models import Group, Permission

PERMISSIONS_MAP = {
    'keys': {
        'SCAN': 'StaticAnalyzer.can_scan',
        'SUPPRESS': 'StaticAnalyzer.can_suppress',
        'DELETE': 'StaticAnalyzer.can_delete',
    },
    'perms': {
        'SCAN': ('can_scan', 'Scan Files'),
        'SUPPRESS': ('can_suppress', 'Suppress Findings'),
        'DELETE': ('can_delete', 'Delete Scans'),
    },
}


def create_authorization_roles():
    """Create Authorization Roles."""
    maintainer, _created = Group.objects.get_or_create(name='Maintainer')
    Group.objects.get_or_create(name='Viewer')

    p = PERMISSIONS_MAP['perms']
    scan_permissions = Permission.objects.filter(codename=p['SCAN'])
    suppress_permissions = Permission.objects.filter(codename=p['SUPPRESS'])
    delete_permissions = Permission.objects.filter(codename=p['DELETE'])

    for p in scan_permissions:
        maintainer.permissions.add(p)
    for p in suppress_permissions:
        maintainer.permissions.add(p)
    for p in delete_permissions:
        maintainer.permissions.add(p)
