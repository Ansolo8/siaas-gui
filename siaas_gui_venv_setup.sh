#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "`readlink -f ${BASH_SOURCE[0]}`" )" &> /dev/null && pwd )

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or using sudo!"
  exit 1
fi

cd ${SCRIPT_DIR}

sudo apt-get install python3 python3-pip python3-tk
python3 -m venv ./venv
source ./venv/bin/activate
pip3 install wheel
#pip3 install -r ./requirements.txt
