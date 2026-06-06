#!/bin/bash
# siaas_gui_venv_setup.sh — install system dependencies and Python venv
# Run once as root before starting the GUI for the first time.

SCRIPT_DIR=$(cd -- "$(dirname -- "$(readlink -f "${BASH_SOURCE[0]}")")" &>/dev/null && pwd)

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or using sudo!"
  exit 1
fi

cd "${SCRIPT_DIR}"

apt-get update -q
apt-get install -y python3 python3-pip python3-venv python3-tk

python3 -m venv ./venv
source ./venv/bin/activate
pip3 install --upgrade pip wheel
pip3 install -r ./requirements.txt

echo "Setup complete. Run ./siaas_gui_run.sh to start the GUI."
