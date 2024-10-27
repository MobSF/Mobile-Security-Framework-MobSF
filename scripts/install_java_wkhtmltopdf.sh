#!/bin/bash

# For apktool
mkdir -p /home/mobsf/.local/share/apktool/framework

if [ "$TARGETPLATFORM" == "linux/arm64" ]
then
    WKH_FILE=$WKH_FILE_ARM
    JDK_FILE=$JDK_FILE_ARM
    LIBSSL_FILE=$LIBSSL_FILE_ARM
fi

echo "Target platform identified as $TARGETPLATFORM"
JDK_URL="https://download.java.net/java/GA/jdk22.0.2/c9ecb94cd31b495da20a27d4581645e8/9/GPL/${JDK_FILE}"
WKH_URL="https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/${WKH_FILE}"
LIBSSL11_URL="http://ftp.us.debian.org/debian/pool/main/o/openssl/${LIBSSL_FILE}"

# Download and install wkhtmltopdf
# Install dependencies for wkhtmltopdf
echo "Installing $LIBSSL_FILE ..."
wget --quiet -O /tmp/${LIBSSL_FILE} "${LIBSSL11_URL}" && \
    dpkg -i /tmp/${LIBSSL_FILE} && \
    rm -f /tmp/${LIBSSL_FILE}

echo "Installing $WKH_FILE ..."
wget --quiet -O /tmp/${WKH_FILE} "${WKH_URL}" && \
    dpkg -i /tmp/${WKH_FILE} && \
    apt-get install -f -y --no-install-recommends && \
    ln -s /usr/local/bin/wkhtmltopdf /usr/bin && \
    rm -f /tmp/${WKH_FILE}

# Install OpenJDK
echo "Installing $JDK_FILE ..."
wget --quiet "${JDK_URL}" && \
    tar zxf "${JDK_FILE}" && \
    rm -f "${JDK_FILE}"

# Delete script
rm $0
