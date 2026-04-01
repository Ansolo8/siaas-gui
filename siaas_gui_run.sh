# siaas/gui/run_gui.sh
#!/bin/bash
cd "$(dirname "$0")"
sudo apt install unifont
sudo bash siaas_gui_venv_setup.sh
python3 siaas_gui.py
