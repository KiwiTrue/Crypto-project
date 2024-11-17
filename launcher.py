
import os
import sys
import subprocess
from time import sleep

def start_game():
    try:
        # Create logs directory if it doesn't exist
        os.makedirs("logs", exist_ok=True)
        
        # Start the main game manager (which includes CA and Codemaster)
        game_process = subprocess.Popen([sys.executable, "main.py"])
        print("Started game server...")
        sleep(2)  # Wait for server to initialize
        
        # Start Player 1
        player1_process = subprocess.Popen([sys.executable, "player.py", "Player1"])
        print("Started Player 1...")
        sleep(1)
        
        # Start Player 2
        player2_process = subprocess.Popen([sys.executable, "player.py", "Player2"])
        print("Started Player 2...")
        
        # Wait for game to complete
        game_process.wait()
        
    except KeyboardInterrupt:
        print("\nShutting down game...")
    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        # Cleanup any remaining processes
        for process in [game_process, player1_process, player2_process]:
            try:
                process.terminate()
            except:
                pass

if __name__ == "__main__":
    start_game()