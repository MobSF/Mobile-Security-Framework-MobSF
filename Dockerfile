#Base image
FROM ubuntu:18.04

#Labels and Credits
LABEL \
    name="MobSF" \
    author="Ajin Abraham <ajin25@gmail.com>" \
    maintainer="Ajin Abraham <ajin25@gmail.com>" \
    contributor_1="OscarAkaElvis <oscar.alfonso.diaz@gmail.com>" \
    contributor_2="Vincent Nadal <vincent.nadal@orange.fr>" \
    description="Mobile Security Framework is an intelligent, all-in-one open source mobile application (Android/iOS/Windows) automated pen-testing framework capable of performing static, dynamic analysis and web API testing"

#Environment vars
ENV DEBIAN_FRONTEND="noninteractive" \
    JDK_FILE="openjdk-12_linux-x64_bin.tar.gz" \
    WKH_FILE="wkhtmltox-0.12.5-dev-163e124_linux-generic-amd64.tar.xz"

ENV JDK_URL="https://download.java.net/java/GA/jdk12/GPL/${JDK_FILE}" \
    WKH_URL="http://www.ajvg.com/downloads/${WKH_FILE}"

#Update the repository sources list
#Install Required Libs
#see https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
RUN apt update -y && apt install -y \
    build-essential \
    git \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    locales \
    sqlite3 \
    fontconfig-config \
    libjpeg-turbo8 \
    libxrender1 \
    libfontconfig1 \ 
    libxext6 \
    fontconfig \
    xfonts-75dpi \
    python3.6 \
    python3-dev \
    python3-pip \
    wget
     
#set locales
RUN locale-gen en_US.UTF-8
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'

#Install Wkhtmltopdf
RUN wget --quiet -O /tmp/wkhtmltox.tar.xz "${WKH_URL}" && \
    tar xJf /tmp/wkhtmltox.tar.xz -C /usr/bin/ --strip-component=2 wkhtmltox/bin/wkhtmltopdf && \
    rm -f /tmp/wkhtmltox.tar.xz

#Install OpenJDK12
RUN wget --quiet "${JDK_URL}" && \
    tar zxf "${JDK_FILE}" && \
    rm -f "${JDK_FILE}"
ENV JAVA_HOME="/jdk-12" 
ENV PATH="$JAVA_HOME/bin:$PATH"

#Add MobSF master
COPY . /root/Mobile-Security-Framework-MobSF
WORKDIR /root/Mobile-Security-Framework-MobSF

#Enable Use Home Directory
RUN sed -i 's/USE_HOME = False/USE_HOME = True/g' MobSF/settings.py

#Kali fix to support 32 bit execution
RUN ./scripts/kali_fix.sh

#Postgres support is set to false by default
ARG POSTGRES=False
#check if Postgres support needs to be enabled 
WORKDIR /root/Mobile-Security-Framework-MobSF/scripts
RUN chmod +x postgres_support.sh; sync; ./postgres_support.sh $POSTGRES
WORKDIR /root/Mobile-Security-Framework-MobSF

#Add apktool working path
RUN mkdir -p /root/.local/share/apktool/framework

#Install APKiD dependencies
RUN pip3 install --quiet --no-cache-dir wheel==0.33.4 && \
    pip3 wheel --quiet --no-cache-dir --wheel-dir=/tmp/yara-python --build-option="build" --build-option="--enable-dex" git+https://github.com/VirusTotal/yara-python.git && \
    pip3 install --quiet --no-cache-dir --no-index --find-links=/tmp/yara-python yara-python

#Install Dependencies
RUN pip3 install --quiet --no-cache-dir -r requirements.txt

#Cleanup
RUN \
    apt remove -y \
        git \
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

#Expose MobSF Port
EXPOSE 8000

RUN python3 manage.py makemigrations && \
    python3 manage.py makemigrations StaticAnalyzer && \
    python3 manage.py migrate

#Run MobSF
CMD ["gunicorn", "-b", "0.0.0.0:8000", "MobSF.wsgi:application", "--workers=1", "--threads=4", "--timeout=1800"]
