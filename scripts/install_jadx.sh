#!/bin/bash
echo '[INSTALL] Installing Jadx'
gh-release-install \
'skylot/jadx' \
'jadx-{version}.zip' \
'/home/mobsf/Mobile-Security-Framework-MobSF/mobsf/StaticAnalyzer/tools/jadx.zip'
if [ -f '/home/mobsf/Mobile-Security-Framework-MobSF/mobsf/StaticAnalyzer/tools/jadx.zip' ]; then
    rm -fr /home/mobsf/Mobile-Security-Framework-MobSF/mobsf/StaticAnalyzer/tools/jadx/
    unzip -qq -d /home/mobsf/Mobile-Security-Framework-MobSF/mobsf/StaticAnalyzer/tools/jadx/ /home/mobsf/Mobile-Security-Framework-MobSF/mobsf/StaticAnalyzer/tools/jadx.zip
    rm -f /home/mobsf/Mobile-Security-Framework-MobSF/mobsf/StaticAnalyzer/tools/jadx.zip
else
    echo '[ERROR] Problem downloading Jadx'
    exit 1
fi
# Delete script
rm $0
