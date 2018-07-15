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
ENV PDFGEN_PKGFILE="wkhtmltox-0.12.4_linux-generic-amd64.tar.xz" 
ENV PDFGEN_URL="https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.4/${PDFGEN_PKGFILE}"
ENV YARA_URL="https://github.com/rednaga/yara-python"

#Update the repository sources list
#Install Required Libs
#see https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
RUN apt update -y && apt install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev

#Install Oracle JDK 8
RUN apt install -y software-properties-common && \
    add-apt-repository ppa:webupd8team/java -y && \
    apt update && \
    echo oracle-java7-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections && \
    apt install -y oracle-java8-installer

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
    xorg

#Install git
RUN \
    apt install -y \
    git

#Install wkhtmltopdf for PDF Reports
WORKDIR /tmp
RUN wget ${PDFGEN_URL} && \
    tar xvf ${PDFGEN_PKGFILE} && \
    cp -r /tmp/wkhtmltox/* /usr/local/

#Add MobSF master
COPY . /root/Mobile-Security-Framework-MobSF

#Enable Use Home Directory
WORKDIR /root/Mobile-Security-Framework-MobSF/MobSF
RUN sed -i 's/USE_HOME = False/USE_HOME = True/g' settings.py

#Kali fix to support 32 bit execution
RUN ./kali_fix.sh

#Install Dependencies
WORKDIR /root/Mobile-Security-Framework-MobSF
RUN pip3 install -r requirements.txt

#Install apkid dependencies, and enable it 
WORKDIR /tmp
RUN git clone ${YARA_URL} && \
    cd yara-python && \
    python3 setup.py install && \
    rm -fr /tmp/yara-python && \
    sed -i 's/APKID_ENABLED.*/APKID_ENABLED = True/' /root/Mobile-Security-Framework-MobSF/MobSF/settings.py

#Cleanup
RUN \
    apt remove -y git && \
    apt clean && \
    apt autoclean && \
    apt autoremove -y
RUN rm -rf /var/lib/apt/lists/* /tmp/* > /dev/null 2>&1

#Expose MobSF Port
EXPOSE 8000

#Run MobSF
WORKDIR /root/Mobile-Security-Framework-MobSF
CMD ["python3","manage.py","runserver","0.0.0.0:8000"]
