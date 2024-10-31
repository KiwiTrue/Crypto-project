# Main.py

import threading
import os
from Codemaster import Codemaster
from GUI import GameGUI

def start_codemasters():
    codemaster = Codemaster()
    codemaster.start_server()

def start_game_gui():
    gui = GameGUI()
    gui.run()

if __name__ == '__main__':
    threading.Thread(target=start_codemasters).start()
    if os.environ.get('DISPLAY'):
        threading.Thread(target=start_game_gui).start()
    else:
        print("No display found. Skipping GUI.")