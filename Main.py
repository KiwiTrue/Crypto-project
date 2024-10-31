# Main.py

import threading
import time
from Codemaster import Codemaster
from Player import Player

def start_codemaster():
    codemaster = Codemaster()
    codemaster.start_server()

def start_player():
    player = Player(name='Player1')
    player.connect_to_server()
    player.play_game()

if __name__ == '__main__':
    # Start the codemaster server in a separate thread
    codemaster_thread = threading.Thread(target=start_codemaster)
    codemaster_thread.start()

    # Give the server a moment to start up
    time.sleep(1)

    # Start the player in the main thread
    start_player()

    # Wait for the codemaster thread to finish
    codemaster_thread.join()
