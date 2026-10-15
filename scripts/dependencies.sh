#!/bin/bash
set -euo pipefail
WKH_FILE=wkhtmltox_0.12.6.1-3.bookworm_amd64.deb
if [ "${TARGETPLATFORM:-linux/amd64}" = "linux/arm64" ]; then
    WKH_FILE=wkhtmltox_0.12.6.1-3.bookworm_arm64.deb
fi

# Java 21 is installed by the Dockerfile from signed Debian packages.
java -version
mkdir -p /home/mobsf/.local/share/apktool/framework
WKH_URL="https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-3/${WKH_FILE}"
wget --quiet -O "/tmp/${WKH_FILE}" "${WKH_URL}"
apt-get install -y --no-install-recommends "/tmp/${WKH_FILE}"
wkhtmltopdf --version
rm -f "/tmp/${WKH_FILE}"

python3 tools_download.py /home/mobsf/.MobSF
test -x /home/mobsf/.MobSF/tools/jadx/jadx-1.5.0/bin/jadx
rm tools_download.py
rm "$0"
