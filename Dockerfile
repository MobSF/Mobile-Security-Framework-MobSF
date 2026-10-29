# Base image
FROM python:3.13-slim-bookworm

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
    JAVA_HOME=/jdk-24.0.2 \
    PATH=/jdk-24.0.2/bin:/root/.local/bin:$PATH \
    DJANGO_SUPERUSER_USERNAME=mobsf \
    DJANGO_SUPERUSER_PASSWORD=mobsf

ARG TARGETPLATFORM

# Create mobsf user and install system/Python dependencies in a single layer
COPY scripts/dependencies.sh mobsf/MobSF/tools_download.py pyproject.toml poetry.lock ./
RUN groupadd --gid $USER_ID $MOBSF_USER && \
    useradd $MOBSF_USER --uid $USER_ID --gid $MOBSF_USER --create-home --home-dir /home/mobsf --shell /bin/false && \
    apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        android-sdk-build-tools \
        android-tools-adb \
        build-essential \
        curl \
        fontconfig \
        fontconfig-config \
        git \
        libfontconfig1 \
        libjpeg62-turbo \
        libxext6 \
        libxrender1 \
        locales \
        python3-dev \
        sqlite3 \
        unzip \
        wget \
        xfonts-75dpi \
        xfonts-base && \
    echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && \
    locale-gen en_US.UTF-8 && \
    update-locale LANG=en_US.UTF-8 && \
    ./dependencies.sh && \
    curl -sSL https://install.python-poetry.org | python3 - && \
    poetry config virtualenvs.create false && \
    poetry install --only main --no-root --no-interaction --no-ansi && \
    poetry cache clear . --all --no-interaction && \
    curl -sSL https://install.python-poetry.org | python3 - --uninstall && \
    rm -f pyproject.toml poetry.lock && \
    chown -R $USER_ID:$USER_ID /home/mobsf && \
    apt-get remove --purge -y \
        build-essential \
        git \
        python3-dev \
        wget && \
    apt-get autoremove --purge -y && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* /root/.cache /root/.local

# Copy source code with final ownership to avoid a duplicate chown layer
WORKDIR /home/mobsf/Mobile-Security-Framework-MobSF
COPY --chown=$USER_ID:$USER_ID . .

HEALTHCHECK CMD curl --fail http://localhost:8000/login/ || exit 1

# Expose MobSF Port and Proxy Port
EXPOSE 8000 1337

# Switch to mobsf user
USER $MOBSF_USER

# Run MobSF
CMD ["/home/mobsf/Mobile-Security-Framework-MobSF/scripts/entrypoint.sh"]
