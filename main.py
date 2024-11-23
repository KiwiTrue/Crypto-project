import logging
import sys
from codemaster import Codemaster
from player import Player
from threading import Thread, Event
from logger import SecurityLogger
import signal
import traceback
from typing import List, Optional
from time import sleep
from secure_protocol import SecureProtocol  # Add this import

class GameManager:
    def __init__(self):
        self.logger = configure_logging()
        self.shutdown_event = Event()
        self.codemaster_thread: Optional[Thread] = None
        self.player_threads: List[Thread] = []
        self.colors = ["Red", "Blue", "Green", "Yellow", "Black", "White"]
        self.server_ready = Event()
        self.player_count = 0

    def signal_handler(self, signum, frame):
        self.logger.log_security_event('shutdown', 'Game shutdown initiated')
        self.shutdown_event.set()
        sys.exit(0)

    def initialize_security(self):
        try:
            # Initialize secure protocol components if needed
            self.logger.log_security_event('security_init', 'Security components initialized')
        except Exception as e:
            self.logger.log_error('security_init_failed', str(e))
            raise

    def start_codemaster(self):
        try:
            codemaster = Codemaster()  # Remove CA parameter
            codemaster.generate_sequence(self.colors)
            print("\nCodemaster initialized and waiting for players...")
            print(f"\nSecret color sequence: {', '.join(codemaster.sequence)}")  # Added this line
            print("Players can now connect using: python player.py <player_name>\n")
            self.logger.log_security_event('codemaster_init', 'Codemaster initialized with sequence')
            self.server_ready.set()
            codemaster.run()
        except Exception as e:
            self.logger.log_error('codemaster_error', str(e))
            self.shutdown_event.set()
            traceback.print_exc()

    def start_player(self, name: str):
        try:
            if not self.server_ready.wait(timeout=5):
                raise TimeoutError("Server failed to start")
            sleep(0.5)
            player = Player(name)  # Remove CA parameter
            self.logger.log_security_event('player_init', f'Player {name} initialized')
            player.play()
        except Exception as e:
            self.logger.log_error('player_error', f'{name}: {str(e)}')
            self.shutdown_event.set()
            traceback.print_exc()

    def run(self):
        try:
            # Initialize security components
            self.initialize_security()
            
            # Setup signal handlers
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
            
            # Only start the codemaster thread
            self.codemaster_thread = Thread(target=self.start_codemaster)
            self.codemaster_thread.daemon = True
            self.codemaster_thread.start()
            
            # Wait for completion or shutdown
            while not self.shutdown_event.is_set():
                self.shutdown_event.wait(1)
                
        except KeyboardInterrupt:
            self.logger.log_security_event('shutdown', 'Game interrupted by user')
        except Exception as e:
            self.logger.log_error('game_error', str(e))
            traceback.print_exc()
        finally:
            self.cleanup()

    def cleanup(self):
        self.shutdown_event.set()
        if self.codemaster_thread and self.codemaster_thread.is_alive():
            self.codemaster_thread.join(timeout=2)
        for thread in self.player_threads:
            if thread.is_alive():
                thread.join(timeout=2)
        self.logger.log_security_event('shutdown', 'Game shutdown complete')

def configure_logging():
    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('mastermind_game.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return SecurityLogger('main')

if __name__ == "__main__":
    game_manager = GameManager()
    game_manager.run()
