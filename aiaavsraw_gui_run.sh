# siaas/gui/aiaavsraw_run_gui.sh
#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"
#sudo apt install unifont
#sudo bash siaas_gui_venv_setup.sh
#python3 siaas_gui.py

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

exec streamlit run aiaavsraw_gui.py --server.address 0.0.0.0 --server.port 8501
