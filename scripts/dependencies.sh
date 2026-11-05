#!/bin/bash
set -e

JDK_FILE=openjdk-24.0.2_linux-x64_bin.tar.gz
JDK_FILE_ARM=openjdk-24.0.2_linux-aarch64_bin.tar.gz

# For apktool
mkdir -p /home/mobsf/.local/share/apktool/framework

if [ "$TARGETPLATFORM" == "linux/arm64" ]
then
    JDK_FILE=$JDK_FILE_ARM
fi

echo "Target platform identified as $TARGETPLATFORM"
JDK_URL="https://download.java.net/java/GA/jdk24.0.2/fdc5d0102fe0414db21410ad5834341f/12/GPL/${JDK_FILE}"

# Install OpenJDK
echo "Installing $JDK_FILE ..."
wget --quiet "${JDK_URL}" && \
    tar zxf "${JDK_FILE}" && \
    rm -f "${JDK_FILE}"

# Install JADX
python3 tools_download.py /home/mobsf/.MobSF
rm tools_download.py

# Delete script
rm $0
