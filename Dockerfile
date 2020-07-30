# Base image
FROM ubuntu:20.04

# Labels and Credits
LABEL \
    name="MobSF" \
    author="Ajin Abraham <ajin25@gmail.com>" \
    maintainer="Ajin Abraham <ajin25@gmail.com>" \
    contributor_1="OscarAkaElvis <oscar.alfonso.diaz@gmail.com>" \
    contributor_2="Vincent Nadal <vincent.nadal@orange.fr>" \
    description="Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis."

# Environment vars
ENV DEBIAN_FRONTEND="noninteractive" \
    ANALYZER_IDENTIFIER="" \
    JDK_FILE="openjdk-12_linux-x64_bin.tar.gz" \
    WKH_FILE="wkhtmltox_0.12.5-1.focal_amd64.deb"

ENV JDK_URL="https://download.java.net/java/GA/jdk12/GPL/${JDK_FILE}" \
    WKH_URL="https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.5/${WKH_FILE}"

# See https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
RUN apt update -y && apt install -y  --no-install-recommends \
    build-essential \
    locales \
    sqlite3 \
    fontconfig-config \
    libjpeg-turbo8 \
    libxrender1 \
    libfontconfig1 \
    libxext6 \
    fontconfig \
    xfonts-75dpi \
    xfonts-base \
    python3.8 \
    python3-dev \
    python3-pip \
    wget \
    android-tools-adb

# Set locales
RUN locale-gen en_US.UTF-8
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'

# Install Wkhtmltopdf
RUN wget --quiet -O /tmp/${WKH_FILE} "${WKH_URL}" && \
    dpkg -i /tmp/${WKH_FILE} && \
    apt-get install -f -y --no-install-recommends && \
    ln -s /usr/local/bin/wkhtmltopdf /usr/bin && \
    rm -f /tmp/${WKH_FILE}

# Install OpenJDK12
RUN wget --quiet "${JDK_URL}" && \
    tar zxf "${JDK_FILE}" && \
    rm -f "${JDK_FILE}"
ENV JAVA_HOME="/jdk-12"
ENV PATH="$JAVA_HOME/bin:$PATH"

WORKDIR /root/Mobile-Security-Framework-MobSF

# Copy source code
COPY . .

# Install Requirements
RUN pip3 install --no-index --find-links=scripts/wheels/ yara-python && \
    pip3 install --quiet --no-cache-dir -r requirements.txt

# Cleanup
RUN \
    apt remove -y \
        libssl-dev \
        libffi-dev \
        libxml2-dev \
        libxslt1-dev \
        python3-dev \
        wget && \
    apt clean && \
    apt autoclean && \
    apt autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* > /dev/null 2>&1 && \
    rm -rf /root/Mobile-Security-Framework-MobSF/scripts/wheels > /dev/null 2>&1

# Enable Use Home Directory and set adb path
RUN sed -i 's/USE_HOME = False/USE_HOME = True/g' MobSF/settings.py && \
    sed -i "s#ADB_BINARY = ''#ADB_BINARY = '/usr/bin/adb'#" MobSF/settings.py

# Postgres support is set to false by default
ARG POSTGRES=False
# Check if Postgres support needs to be enabled
WORKDIR /root/Mobile-Security-Framework-MobSF/scripts
RUN chmod +x postgres_support.sh; sync; ./postgres_support.sh $POSTGRES
WORKDIR /root/Mobile-Security-Framework-MobSF

# Add apktool working path
RUN mkdir -p /root/.local/share/apktool/framework

# Expose MobSF Port
EXPOSE 8000
# MobSF Proxy
EXPOSE 1337

RUN python3 manage.py makemigrations && \
    python3 manage.py makemigrations StaticAnalyzer && \
    python3 manage.py migrate

# Run MobSF
CMD ["gunicorn", "-b", "0.0.0.0:8000", "MobSF.wsgi:application", "--workers=1", "--threads=10", "--timeout=1800"]
