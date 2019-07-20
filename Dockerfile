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
ENV DEBIAN_FRONTEND="noninteractive"
ENV PDFGEN_PKGFILE="wkhtmltox_0.12.5-1.bionic_amd64.deb" 
ENV PDFGEN_URL="https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.5/${PDFGEN_PKGFILE}"

#Update the repository sources list
#Install Required Libs
#see https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
RUN apt update -y && apt install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    locales \
    wget

#set locales
RUN locale-gen en_US.UTF-8
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'

#Install OpenJDK12
RUN wget --quiet https://download.java.net/java/GA/jdk12/GPL/openjdk-12_linux-x64_bin.tar.gz && \
    tar zxvf openjdk-12_linux-x64_bin.tar.gz
ENV JAVA_HOME=/jdk-12
ENV PATH=$JAVA_HOME/bin:$PATH

#Install Python 3
RUN \
    apt install -y \
    python3.6 \
    python3-dev \
    python3-setuptools && \
    python3 /usr/lib/python3/dist-packages/easy_install.py pip

#Install git, sqlite3 client and pdf generator needed dependencies
RUN \
    apt install -y \
    sqlite3 \
    fontconfig-config \
    libjpeg-turbo8 \
    fontconfig \
    xorg \
    xfonts-75dpi \
    git

#Install wkhtmltopdf for PDF Reports
WORKDIR /tmp
RUN wget --quiet ${PDFGEN_URL} && \
    dpkg -i ${PDFGEN_PKGFILE} && \
    rm -rf ${PDFGEN_PKGFILE}

   
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
RUN cd scripts && chmod +x postgres_support.sh; sync; ./postgres_support.sh $POSTGRES

#Add apktool working path
RUN mkdir -p /root/.local/share/apktool/framework

#Install APKiD dependencies
RUN pip3 install wheel
RUN pip3 wheel --wheel-dir=/tmp/yara-python --build-option="build" --build-option="--enable-dex" git+https://github.com/VirusTotal/yara-python.git@v3.10.0
RUN pip3 install --no-index --find-links=/tmp/yara-python yara-python

#Install Dependencies
RUN pip3 install -r requirements.txt

#Cleanup
RUN \
    apt remove -y git && \
    apt clean && \
    apt autoclean && \
    apt autoremove -y
RUN rm -rf /var/lib/apt/lists/* /tmp/* > /dev/null 2>&1

#Expose MobSF Port
EXPOSE 8000

RUN python3 manage.py makemigrations
RUN python3 manage.py migrate

#Run MobSF
CMD ["gunicorn", "-b", "0.0.0.0:8000", "MobSF.wsgi:application", "--workers=1", "--threads=4", "--timeout=1800"]
