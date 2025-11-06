# Installation Guide (18)

## Prerequisites
- Python 3.11, Node 18, Docker 24.
- PostgreSQL 15 with TLS enabled.

## macOS
- Use `brew bundle` to install dependencies.
- Run `./setup.sh --profile macos`.

## Linux
- `apt-get install build-essential libmagic-dev`.
- Run `./setup.sh --profile linux`.

## Windows
- Use WSL2 with Ubuntu 22.04.
- Execute `setup.bat` followed by `wsl_setup.ps1` for virtualization drivers.

Production deployments follow `docker/README.md` plus `docs/security/container_security.md` hardening steps.
