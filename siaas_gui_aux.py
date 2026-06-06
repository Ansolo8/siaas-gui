# siaas/aiaavsraw-gui/aiaavsraw_aux.py
import json
import os

def read_from_local_file(filepath):
    """Lê dados de um arquivo JSON local"""
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def write_to_local_file(filepath, data):
    """Escreve dados em um arquivo JSON local"""
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception:
        return False
