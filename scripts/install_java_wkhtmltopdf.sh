#!/bin/bash
if [ "$TARGETPLATFORM" == "linux/arm64" ]
then
    WKH_FILE=$WKH_FILE_ARM
    JDK_FILE=$JDK_FILE_ARM
    apt install -y git
    pip3 install wheel
    pip3 wheel --wheel-dir=yara-python-dex git+https://github.com/MobSF/yara-python-dex.git
    pip3 install --no-index --find-links=yara-python-dex yara-python-dex
    rm -rf yara-python-dex
fi

echo "Target platform identified as $TARGETPLATFORM"

JDK_URL="https://download.java.net/java/GA/jdk16.0.1/7147401fd7354114ac51ef3e1328291f/9/GPL/${JDK_FILE}"
WKH_URL="https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6-1/${WKH_FILE}"

#Download and install wkhtmltopdf
echo "Installing $WKH_FILE ..."
wget --quiet -O /tmp/${WKH_FILE} "${WKH_URL}" && \
    dpkg -i /tmp/${WKH_FILE} && \
    apt-get install -f -y --no-install-recommends && \
    ln -s /usr/local/bin/wkhtmltopdf /usr/bin && \
    rm -f /tmp/${WKH_FILE}

# Install OpenJDK12
echo "Installing $JDK_FILE ..."
wget --quiet "${JDK_URL}" && \
    tar zxf "${JDK_FILE}" && \
    rm -f "${JDK_FILE}"

# Delete script
rm $0