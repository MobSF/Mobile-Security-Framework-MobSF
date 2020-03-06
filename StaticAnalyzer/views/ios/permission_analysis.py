import logging

logger = logging.getLogger(__name__)


def check_permissions(p_list):
    """Check the permissions the app requests."""
    # List taken from
    # https://developer.apple.com/library/content/
    # documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html
    logger.info('Checking Permissions')
    permissions = []
    if 'NSAppleMusicUsageDescription' in p_list:
        permissions.append({
            'name': 'NSAppleMusicUsageDescription',
            'description': 'Access Apple Media Library.',
            'reason': p_list['NSAppleMusicUsageDescription'],
        })
    if 'NSBluetoothPeripheralUsageDescription' in p_list:
        permissions.append({
            'name': 'NSBluetoothPeripheralUsageDescription',
            'description': 'Access Bluetooth Interface.',
            'reason': p_list['NSBluetoothPeripheralUsageDescription'],
        })
    if 'NSCalendarsUsageDescription' in p_list:
        permissions.append({
            'name': 'NSCalendarsUsageDescription',
            'description': 'Access Calendars.',
            'reason': p_list['NSCalendarsUsageDescription'],
        })
    if 'NSCameraUsageDescription' in p_list:
        permissions.append({
            'name': 'NSCameraUsageDescription',
            'description': 'Access the Camera.',
            'reason': p_list['NSCameraUsageDescription'],
        })
    if 'NSContactsUsageDescription' in p_list:
        permissions.append({
            'name': 'NSContactsUsageDescription',
            'description': 'Access Contacts.',
            'reason': p_list['NSContactsUsageDescription'],
        })
    if 'NSHealthShareUsageDescription' in p_list:
        permissions.append({
            'name': 'NSHealthShareUsageDescription',
            'description': 'Read Health Data.',
            'reason': p_list['NSHealthShareUsageDescription'],
        })
    if 'NSHealthUpdateUsageDescription' in p_list:
        permissions.append({
            'name': 'NSHealthUpdateUsageDescription',
            'description': 'Write Health Data.',
            'reason': p_list['NSHealthUpdateUsageDescription'],
        })
    if 'NSHomeKitUsageDescription' in p_list:
        permissions.append({
            'name': 'NSHomeKitUsageDescription',
            'description': 'Access HomeKit configuration data.',
            'reason': p_list['NSHomeKitUsageDescription'],
        })
    if 'NSLocationAlwaysUsageDescription' in p_list:
        permissions.append({
            'name': 'NSLocationAlwaysUsageDescription',
            'description': 'Access location information at all times.',
            'reason': p_list['NSLocationAlwaysUsageDescription'],
        })
    if 'NSLocationUsageDescription' in p_list:
        permissions.append({
            'name': 'NSLocationUsageDescription',
            'description': ('Access location information'
                            ' at all times (< iOS 8).'),
            'reason': p_list['NSLocationUsageDescription'],
        })
    if 'NSLocationWhenInUseUsageDescription' in p_list:
        permissions.append({
            'name': 'NSLocationWhenInUseUsageDescription',
            'description': ('Access location information when'
                            ' app is in the foreground.'),
            'reason': p_list['NSLocationWhenInUseUsageDescription'],
        })
    if 'NSMicrophoneUsageDescription' in p_list:
        permissions.append({
            'name': 'NSMicrophoneUsageDescription',
            'description': 'Access microphone.',
            'reason': p_list['NSMicrophoneUsageDescription'],
        })
    if 'NSMotionUsageDescription' in p_list:
        permissions.append({
            'name': 'NSMotionUsageDescription',
            'description': 'Access the device’s accelerometer.',
            'reason': p_list['NSMotionUsageDescription'],
        })
    if 'NSPhotoLibraryUsageDescription' in p_list:
        permissions.append({
            'name': 'NSPhotoLibraryUsageDescription',
            'description': 'Access the user’s photo library.',
            'reason': p_list['NSPhotoLibraryUsageDescription'],
        })
    if 'NSRemindersUsageDescription' in p_list:
        permissions.append({
            'name': 'NSRemindersUsageDescription',
            'description': 'Access the user’s reminders.',
            'reason': p_list['NSRemindersUsageDescription'],
        })
    if 'NSVideoSubscriberAccountUsageDescription' in p_list:
        permissions.append({
            'name': 'NSVideoSubscriberAccountUsageDescription',
            'description': 'Access the user’s TV provider account.',
            'reason': p_list['NSVideoSubscriberAccountUsageDescription'],
        })
    if 'NSFaceIDUsageDescription' in p_list:
        permissions.append({
            'name': 'NSFaceIDUsageDescription',
            'description': 'Access the ability to authenticate with Face ID.',
            'reason': p_list['NSFaceIDUsageDescription'],
        })

    return permissions
