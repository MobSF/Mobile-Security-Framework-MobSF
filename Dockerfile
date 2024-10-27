# Base image
FROM python:3.12-slim-bookworm

LABEL \
    name="MobSF" \
    author="Ajin Abraham <ajin25@gmail.com>" \
    maintainer="Ajin Abraham <ajin25@gmail.com>" \
    contributor_1="OscarAkaElvis <oscar.alfonso.diaz@gmail.com>" \
    contributor_2="Vincent Nadal <vincent.nadal@orange.fr>" \
    description="Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis."

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    MOBSF_USER=mobsf \
    USER_ID=9901 \
    MOBSF_PLATFORM=docker \
    MOBSF_ADB_BINARY=/usr/bin/adb \
    JDK_FILE=openjdk-22.0.2_linux-x64_bin.tar.gz \
    JDK_FILE_ARM=openjdk-22.0.2_linux-aarch64_bin.tar.gz \
    LIBSSL_FILE=libssl1.1_1.1.1w-0+deb11u1_amd64.deb \
    LIBSSL_FILE_ARM=libssl1.1_1.1.1w-0+deb11u1_arm64.deb \
    WKH_FILE=wkhtmltox_0.12.6.1-2.bullseye_amd64.deb \
    WKH_FILE_ARM=wkhtmltox_0.12.6.1-2.bullseye_arm64.deb \
    JAVA_HOME=/jdk-22.0.2 \
    PATH=$JAVA_HOME/bin:/root/.local/bin:$PATH \
    DJANGO_SUPERUSER_USERNAME=mobsf \
    DJANGO_SUPERUSER_PASSWORD=mobsf

# See https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
RUN apt update -y && \
    apt install -y --no-install-recommends \
    build-essential \
    locales \
    sqlite3 \
    fontconfig-config \
    libjpeg62-turbo \
    libxrender1 \
    libfontconfig1 \
    libxext6 \
    fontconfig \
    xfonts-75dpi \
    xfonts-base \
    python3-dev \
    python3-pip \
    wget \
    curl \
    git \
    jq \
    unzip \
    android-tools-adb && \
    echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && \
    locale-gen en_US.UTF-8 && \
    update-locale LANG=en_US.UTF-8 && \
    apt upgrade -y && \
    curl -sSL https://install.python-poetry.org | python3 - && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/*

ARG TARGETPLATFORM
COPY scripts/install_java_wkhtmltopdf.sh poetry.lock pyproject.toml ./

# Install wkhtmltopdf & OpenJDK
RUN ./install_java_wkhtmltopdf.sh

# Install Python dependencies
RUN poetry config virtualenvs.create false && \
  # Let poetry resolve yara-python-dex with appropriate platform architecture
  poetry add yara-python-dex && \
  poetry install --only main --no-root --no-interaction --no-ansi && \
  poetry cache clear --all pypi && \
  rm -rf /root/.cache/pip

# Cleanup
RUN \
    apt remove -y \
        python3-dev \
        wget && \
    apt clean && \
    apt autoclean && \
    apt autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* > /dev/null 2>&1

# Copy source code
WORKDIR /home/mobsf/Mobile-Security-Framework-MobSF
COPY . .

HEALTHCHECK CMD curl --fail http://host.docker.internal:8000/ || exit 1

# Expose MobSF Port and Proxy Port
EXPOSE 8000 1337

# Create mobsf user
RUN groupadd --gid $USER_ID $MOBSF_USER && \
    useradd $MOBSF_USER --uid $USER_ID --gid $MOBSF_USER --shell /bin/false && \
    chown -R $MOBSF_USER:$MOBSF_USER /home/mobsf

# Switch to mobsf user
USER $MOBSF_USER

# Run MobSF
CMD ["/home/mobsf/Mobile-Security-Framework-MobSF/scripts/entrypoint.sh"]
