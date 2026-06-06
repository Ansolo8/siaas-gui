#!/bin/bash
# siaas_gui_run.sh — start the SIAAS Web GUI
set -euo pipefail

cd "$(dirname "$0")"

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q

exec streamlit run siaas_gui.py --server.address 0.0.0.0 --server.port 8501
