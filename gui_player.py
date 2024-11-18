import tkinter as tk
from tkinter import ttk, messagebox
from player import Player
from CA import CertificationAuthority
from gui_elements import GameWindow, ColorPicker
import threading
import queue

class GUIPlayer:
    def __init__(self, player_name: str):
        self.root = tk.Tk()
        self.root.title(f"Mastermind - Player {player_name}")
        self.message_queue = queue.Queue()
        
        # Create main game window
        self.game_window = GameWindow(self.root)
        
        # Create color picker
        self.color_picker = ColorPicker(self.root, 
                                      ["RED", "BLUE", "GREEN", "YELLOW", "BLACK", "WHITE"])
        
        # Initialize network connection in separate thread
        self.network_thread = threading.Thread(
            target=self._initialize_network, 
            args=(player_name,),
            daemon=True
        )
        self.network_thread.start()
        
        # Setup periodic queue check
        self.root.after(100, self._check_message_queue)
        
    def _initialize_network(self, player_name: str):
        try:
            ca = CertificationAuthority()
            self.player = Player(player_name, ca)
            self.player.on_message = self._handle_server_message
            self.message_queue.put(("status", "Connected to server"))
        except Exception as e:
            self.message_queue.put(("error", f"Connection failed: {str(e)}"))
            
    def _handle_server_message(self, message: str):
        self.message_queue.put(("server", message))
        
    def _check_message_queue(self):
        try:
            while True:
                msg_type, message = self.message_queue.get_nowait()
                if msg_type == "error":
                    messagebox.showerror("Error", message)
                elif msg_type == "server":
                    self.game_window.add_message(message)
                elif msg_type == "status":
                    self.game_window.add_status(message)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._check_message_queue)
            
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    import sys
    player_name = sys.argv[1] if len(sys.argv) > 1 else "Player"
    gui = GUIPlayer(player_name)
    gui.run()
