FROM ubuntu:16.04

MAINTAINER Ajin Abraham <ajin25@gmail.com>

# Update the repository sources list
RUN apt-get update -y

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

#Cleanup
RUN \
  rm -rf /var/lib/apt/lists/*

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

#Expose MobSF Port
EXPOSE 8000

#Run MobSF
WORKDIR /root/Mobile-Security-Framework-MobSF
CMD ["python","manage.py","runserver","0.0.0.0:8000"]
