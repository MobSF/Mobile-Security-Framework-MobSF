#!/bin/bash
set -e

JDK_FILE=openjdk-27.0.1.1_linux-x64_bin.tar.gz
JDK_SHA256=82172b79a4e4a8546e2538c525b63e020f419922a5d30f9873bbb832ce95637b
JDK_FILE_ARM=openjdk-27.0.1.1_linux-aarch64_bin.tar.gz
JDK_SHA256_ARM=7b851f4cdf55ce48dc33584349177aa271df0bbd0ff5711a6e7fcd812ef5a90a

# For apktool
mkdir -p /home/mobsf/.local/share/apktool/framework

if [ "$TARGETPLATFORM" == "linux/arm64" ]
then
    JDK_FILE=$JDK_FILE_ARM
    JDK_SHA256=$JDK_SHA256_ARM
fi

echo "Target platform identified as $TARGETPLATFORM"
JDK_URL="https://download.java.net/java/GA/jdk27.0.1.1/c3a705caf5044be8aa0b09e62be69b20/4/GPL/${JDK_FILE}"

# Install OpenJDK
echo "Installing $JDK_FILE ..."
wget --quiet "${JDK_URL}"
echo "${JDK_SHA256}  ${JDK_FILE}" | sha256sum -c -
tar zxf "${JDK_FILE}"
rm -f "${JDK_FILE}"

# Install JADX
python3 tools_download.py /home/mobsf/.MobSF
rm tools_download.py

# Delete script
rm $0
