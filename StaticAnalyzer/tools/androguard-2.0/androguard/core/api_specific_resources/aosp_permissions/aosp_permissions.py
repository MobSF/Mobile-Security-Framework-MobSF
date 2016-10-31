import androguard.core.api_specific_resources.aosp_permissions.aosp_permissions_api9 as api9
import androguard.core.api_specific_resources.aosp_permissions.aosp_permissions_api10 as api10
import androguard.core.api_specific_resources.aosp_permissions.aosp_permissions_api14 as api14
import androguard.core.api_specific_resources.aosp_permissions.aosp_permissions_api15 as api15
import androguard.core.api_specific_resources.aosp_permissions.aosp_permissions_api16 as api16
import androguard.core.api_specific_resources.aosp_permissions.aosp_permissions_api17 as api17
import androguard.core.api_specific_resources.aosp_permissions.aosp_permissions_api18 as api18
import androguard.core.api_specific_resources.aosp_permissions.aosp_permissions_api19 as api19
import androguard.core.api_specific_resources.aosp_permissions.aosp_permissions_api21 as api21
import androguard.core.api_specific_resources.aosp_permissions.aosp_permissions_api22 as api22


AOSP_PERMISSIONS = {
    "9": {"AOSP_PERMISSIONS" : api9.AOSP_PERMISSIONS, "AOSP_PERMISSIONS_GROUPS": api9.AOSP_PERMISSION_GROUPS},
    "10": {"AOSP_PERMISSIONS" : api10.AOSP_PERMISSIONS, "AOSP_PERMISSIONS_GROUPS": api10.AOSP_PERMISSION_GROUPS},
    "14": {"AOSP_PERMISSIONS" : api14.AOSP_PERMISSIONS, "AOSP_PERMISSIONS_GROUPS": api14.AOSP_PERMISSION_GROUPS},
    "15": {"AOSP_PERMISSIONS" : api15.AOSP_PERMISSIONS, "AOSP_PERMISSIONS_GROUPS": api15.AOSP_PERMISSION_GROUPS},
    "16": {"AOSP_PERMISSIONS" : api16.AOSP_PERMISSIONS, "AOSP_PERMISSIONS_GROUPS": api16.AOSP_PERMISSION_GROUPS},
    "17": {"AOSP_PERMISSIONS" : api17.AOSP_PERMISSIONS, "AOSP_PERMISSIONS_GROUPS": api17.AOSP_PERMISSION_GROUPS},
    "18": {"AOSP_PERMISSIONS" : api18.AOSP_PERMISSIONS, "AOSP_PERMISSIONS_GROUPS": api18.AOSP_PERMISSION_GROUPS},
    "19": {"AOSP_PERMISSIONS" : api19.AOSP_PERMISSIONS, "AOSP_PERMISSIONS_GROUPS": api19.AOSP_PERMISSION_GROUPS},
    "21": {"AOSP_PERMISSIONS" : api21.AOSP_PERMISSIONS, "AOSP_PERMISSIONS_GROUPS": api21.AOSP_PERMISSION_GROUPS},
    "22": {"AOSP_PERMISSIONS" : api22.AOSP_PERMISSIONS, "AOSP_PERMISSIONS_GROUPS": api22.AOSP_PERMISSION_GROUPS},
}
