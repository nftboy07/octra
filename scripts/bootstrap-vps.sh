#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script as root." >&2
  exit 1
fi

: "${REPO_URL:?Set REPO_URL to the GitHub repository URL.}"
: "${COMMIT:?Set COMMIT to the commit SHA to deploy.}"

APP_USER="${APP_USER:-octra}"
INSTALL_ROOT="${INSTALL_ROOT:-/home/${APP_USER}/octra_investigation}"
TOOLKIT_DIR="${INSTALL_ROOT}/toolkit"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  git \
  python3 \
  python3-pip \
  python3-venv

if ! id -u "${APP_USER}" >/dev/null 2>&1; then
  useradd --create-home --user-group --shell /bin/bash "${APP_USER}"
fi

install -d -o "${APP_USER}" -g "${APP_USER}" "${INSTALL_ROOT}"

if [[ -e "${TOOLKIT_DIR}" && ! -d "${TOOLKIT_DIR}/.git" ]]; then
  echo "Refusing to overwrite non-Git directory: ${TOOLKIT_DIR}" >&2
  exit 1
fi

if [[ ! -d "${TOOLKIT_DIR}/.git" ]]; then
  runuser -u "${APP_USER}" -- git -c protocol.file.allow=never clone \
    --branch main --single-branch --no-tags "${REPO_URL}" "${TOOLKIT_DIR}"
else
  runuser -u "${APP_USER}" -- git -C "${TOOLKIT_DIR}" remote set-url origin "${REPO_URL}"
  runuser -u "${APP_USER}" -- git -C "${TOOLKIT_DIR}" fetch --prune origin main
fi

runuser -u "${APP_USER}" -- git -C "${TOOLKIT_DIR}" checkout --detach --no-recurse-submodules "${COMMIT}"
runuser -u "${APP_USER}" -- git -C "${TOOLKIT_DIR}" config --local submodule.recurse false

runuser -u "${APP_USER}" -- python3 -m venv "${TOOLKIT_DIR}/.venv"
runuser -u "${APP_USER}" -- "${TOOLKIT_DIR}/.venv/bin/python" -m pip install \
  --disable-pip-version-check --no-input "setuptools>=68"
runuser -u "${APP_USER}" -- "${TOOLKIT_DIR}/.venv/bin/python" -m pip install \
  --disable-pip-version-check --no-input --no-build-isolation --no-deps -e "${TOOLKIT_DIR}"

WORKSPACE="${INSTALL_ROOT}"
runuser -u "${APP_USER}" -- "${TOOLKIT_DIR}/.venv/bin/octra-recon" init --workspace "${WORKSPACE}"
runuser -u "${APP_USER}" -- "${TOOLKIT_DIR}/.venv/bin/octra-recon" sources sync --workspace "${WORKSPACE}"
runuser -u "${APP_USER}" -- "${TOOLKIT_DIR}/.venv/bin/octra-recon" inventory --workspace "${WORKSPACE}"

echo "Deployment complete: ${TOOLKIT_DIR} at ${COMMIT}"
