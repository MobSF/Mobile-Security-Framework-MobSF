import logging

logger = logging.getLogger(__name__)

# List taken from
# https://developer.apple.com/library/archive/documentation/
# General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html

COCOA_KEYS = {
    'NETestAppMapping': (
        ('Enables testing of per-app VPN app extensions '
         'without using an MDM server.'),
        'normal'),
    'NFCReaderUsageDescription': (
        'Access device’s NFC reader.',
        'dangerous'),
    'NSAppleMusicUsageDescription': (
        'Access Apple Media Library.',
        'dangerous'),
    'NSBluetoothPeripheralUsageDescription': (
        'Access Bluetooth Interface.',
        'dangerous'),
    'NSCalendarsUsageDescription': (
        'Access Calendars.',
        'dangerous'),
    'NSCameraUsageDescription': (
        'Access the Camera.',
        'dangerous'),
    'NSContactsUsageDescription': (
        'Access Contacts.',
        'dangerous'),
    'NSFaceIDUsageDescription': (
        'Access the ability to authenticate with Face ID.',
        'normal'),
    'NSHealthClinicalHealthRecordsShareUsageDescription': (
        'Access user’s clinical health records.',
        'dangerous'),
    'NSHealthShareUsageDescription': (
        'Read Health Data.',
        'dangerous'),
    'NSHealthUpdateUsageDescription': (
        'Write Health Data.',
        'dangerous'),
    'NSHomeKitUsageDescription': (
        'Access HomeKit configuration data.',
        'dangerous'),
    'NSLocationAlwaysUsageDescription': (
        'Access location information at all times.',
        'dangerous'),
    'NSLocationUsageDescription': (
        'Access location information at all times (< iOS 8).',
        'dangerous'),
    'NSLocationWhenInUseUsageDescription': (
        'Access location information when app is in the foreground.',
        'dangerous'),
    'NSMicrophoneUsageDescription': (
        'Access microphone.',
        'dangerous'),
    'NSMotionUsageDescription': (
        'Access the device’s accelerometer.',
        'dangerous'),
    'NSPhotoLibraryUsageDescription': (
        'Access the user’s photo library.',
        'dangerous'),
    'NSRemindersUsageDescription': (
        'Access the user’s reminders.',
        'dangerous'),
    'NSSiriUsageDescription': (
        'Allow app to send user data to Siri',
        'dangerous'),
    'NSSpeechRecognitionUsageDescription': (
        'Allow app to send user data to Apple’s speech recognition servers.',
        'normal'),
    'NSVideoSubscriberAccountUsageDescription': (
        'Access the user’s TV provider account.',
        'normal'),
    'NSLocalNetworkUsageDescription': (
        'Allow app to request access to the local network.',
        'normnal'),
}


def check_permissions(p_list):
    """Check the permissions the app requests."""
    permissions = {}
    for perm, desc in COCOA_KEYS.items():
        if perm in p_list:
            permissions[perm] = {
                'info': desc[0],
                'status': desc[1],
                'description': p_list.get(perm, ''),
            }
    return permissions
