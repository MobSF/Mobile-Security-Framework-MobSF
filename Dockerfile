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
ENV YARA_URL="https://github.com/rednaga/yara-python-1"

#Postgres support is set to false by default
ARG POSTGRES=False

#Update the repository sources list
#Install Required Libs
#see https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
RUN apt update -y && apt install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev

#Install Oracle JDK11 LTS
RUN apt install -y software-properties-common && \
    add-apt-repository ppa:linuxuprising/java -y && \
    apt update && \
    echo oracle-java11-installer shared/accepted-oracle-license-v1-2 select true | /usr/bin/debconf-set-selections && \
    apt install -y oracle-java11-installer

#Install Python 3
RUN \
    apt install -y \
    python3.6 \
    python3-dev \
    python3-setuptools && \
    python3 /usr/lib/python3/dist-packages/easy_install.py pip

#Install sqlite3 client and pdf generator needed dependencies
RUN \
    apt install -y \
    sqlite3 \
    fontconfig-config \
    libjpeg-turbo8 \
    fontconfig \
    xorg \
    xfonts-75dpi

#Install git
RUN \
    apt install -y \
    git

#Install wkhtmltopdf for PDF Reports
WORKDIR /tmp
RUN wget ${PDFGEN_URL} && \
    dpkg -i ${PDFGEN_PKGFILE}
   
#Add MobSF master
COPY . /root/Mobile-Security-Framework-MobSF

#Enable Use Home Directory
WORKDIR /root/Mobile-Security-Framework-MobSF/MobSF
RUN sed -i 's/USE_HOME = False/USE_HOME = True/g' settings.py

#Kali fix to support 32 bit execution
WORKDIR /root/Mobile-Security-Framework-MobSF/scripts
RUN ./kali_fix.sh

#Install Dependencies
WORKDIR /root/Mobile-Security-Framework-MobSF
RUN pip3 install -r requirements.txt

#check if Postgres support must be enabled 
WORKDIR /root/Mobile-Security-Framework-MobSF/scripts
RUN chmod +x ./postgres_support.sh; sync; ./postgres_support.sh $POSTGRES

#Install apkid dependencies, and enable it 
WORKDIR /tmp
RUN git clone --recursive ${YARA_URL} yara-python && \
    cd yara-python && \
    python3 setup.py build --enable-dex install && \
    pip3 install apkid && \
    rm -fr /tmp/yara-python && \
    sed -i 's/APKID_ENABLED.*/APKID_ENABLED = True/' /root/Mobile-Security-Framework-MobSF/MobSF/settings.py

#update apkid rules
WORKDIR /tmp
RUN git clone https://github.com/rednaga/APKiD.git && \
    cd APKiD && \
    python3 prep-release.py && \
    cp apkid/rules/rules.yarc /root/Mobile-Security-Framework-MobSF/MalwareAnalyzer/ && \
    sed -i 's#RULES_DIR =.*#RULES_DIR =  "/root/Mobile-Security-Framework-MobSF/MalwareAnalyzer"#' /usr/local/lib/python3.6/dist-packages/apkid/rules.py && \
    cd .. && \
    rm -fr APKiD

#Add apktool working path
RUN mkdir -p /root/.local/share/apktool/framework

#Cleanup
RUN \
    apt remove -y git && \
    apt clean && \
    apt autoclean && \
    apt autoremove -y
RUN rm -rf /var/lib/apt/lists/* /tmp/* > /dev/null 2>&1

#Expose MobSF Port
EXPOSE 8000

WORKDIR /root/Mobile-Security-Framework-MobSF

#Run MobSF
CMD ["python3","manage.py","runserver","0.0.0.0:8000"]
