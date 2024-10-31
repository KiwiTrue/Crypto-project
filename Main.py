# Main.py

import threading
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
    threading.Thread(target=start_game_gui).start()