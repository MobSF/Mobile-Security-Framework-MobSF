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
    JDK_FILE="openjdk-16.0.1_linux-x64_bin.tar.gz" \
    JDK_FILE_ARM="openjdk-16.0.1_linux-aarch64_bin.tar.gz" \
    WKH_FILE="wkhtmltox_0.12.6-1.focal_amd64.deb" \
    WKH_FILE_ARM="wkhtmltox_0.12.6-1.focal_arm64.deb" \
    JAVA_HOME="/jdk-16.0.1" \
    PATH="$JAVA_HOME/bin:$PATH"

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
    python3.9 \
    python3-dev \
    python3-pip \
    wget \
    git \
    android-tools-adb

# Set locales
RUN locale-gen en_US.UTF-8
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'

# Install wkhtmltopdf & OpenJDK
ARG TARGETPLATFORM

COPY scripts/install_java_wkhtmltopdf.sh .
RUN ./install_java_wkhtmltopdf.sh

WORKDIR /root/Mobile-Security-Framework-MobSF

# Install Requirements
COPY requirements.txt .
RUN pip3 install --upgrade setuptools pip && \
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
    rm -rf /var/lib/apt/lists/* /tmp/* > /dev/null 2>&1

# Copy source code
COPY . .

# Set adb binary path and apktool directory
RUN sed -i "s#ADB_BINARY = ''#ADB_BINARY = '/usr/bin/adb'#" mobsf/MobSF/settings.py && \
    mkdir -p /root/.local/share/apktool/framework

# Postgres support is set to false by default
ARG POSTGRES=False

ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=password
ENV POSTGRES_DB=mobsf
ENV POSTGRES_HOST=postgres

# Check if Postgres support needs to be enabled
RUN ./scripts/postgres_support.sh $POSTGRES

# Expose MobSF Port and Proxy Port
EXPOSE 8000 8000 1337 1337

# Run MobSF
CMD ["/root/Mobile-Security-Framework-MobSF/scripts/entrypoint.sh"]
