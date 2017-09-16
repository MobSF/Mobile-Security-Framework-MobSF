FROM ubuntu:17.04

LABEL maintainer="Ajin Abraham <ajin25@gmail.com>"

ENV PDFGEN_PKGFILE="wkhtmltox-0.12.4_linux-generic-amd64.tar.xz" 
ENV PDFGEN_URL="https://downloads.wkhtmltopdf.org/0.12/0.12.4/${PDFGEN_PKGFILE}"

#Update the repository sources list
RUN apt-get update -y

#Install xorg (needed for pdf generation)
RUN apt-get install -y xorg

#Install Git and required Libs
RUN apt-get install -y \
    git \
    build-essential \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev

#Install Oracle JDK 8
RUN apt-get install -y software-properties-common && \
    add-apt-repository ppa:webupd8team/java -y && \
    apt-get update && \
    echo oracle-java7-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections && \
    apt-get install -y oracle-java8-installer && \
    apt-get clean

#Install Python, pip
RUN \
    apt-get install -y \
    python \
    python-dev \
    python-pip && \
    pip install --upgrade pip

#Install sqlite client and pdf generator needed dependencies
RUN \
    apt-get install -y \
    sqlite3 \
    fontconfig-config \
    libjpeg-turbo8 \
    fontconfig 

#Clone MobSF master
WORKDIR /root
RUN git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git

#Enable Virtualenv and Install Dependencies
WORKDIR /root/Mobile-Security-Framework-MobSF
RUN pip install -r requirements.txt && \
    pip install html5lib==1.0b8

#Enable Use Home Directory
WORKDIR /root/Mobile-Security-Framework-MobSF/MobSF
RUN sed -i 's/USE_HOME = False/USE_HOME = True/g' settings.py

# need to apply Kali fix on docker image to remove error
RUN ./kali_fix.sh

#Cleanup
RUN rm -rf /var/lib/apt/lists/*

#Install pdf generator
WORKDIR /tmp
RUN wget ${PDFGEN_URL} && \
    tar xvf ${PDFGEN_PKGFILE} && \
    rm -rf ${PDFGEN_PKGFILE} 2>/dev/null && \
    cp -r   /tmp/wkhtmltox/* /usr/local/ && \
    rm -fr /tmp/wkhtmltox

#Expose MobSF Port
EXPOSE 8000

#Run MobSF
WORKDIR /root/Mobile-Security-Framework-MobSF
CMD ["python","manage.py","runserver","0.0.0.0:8000"]
