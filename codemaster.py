import socket
import random  # Add this import
from typing import List, Dict, Optional, Tuple
from threading import Lock, Thread
from cryptography.hazmat.primitives.asymmetric import rsa
from session import GameSession
from logger import SecurityLogger
import traceback
import json
import os
from ciphers import caesar_encrypt, aes_encrypt
from ciphers import SecureMessage

class Codemaster:
    def __init__(self, ca, host='0.0.0.0', port=12345):  # Changed to listen on all interfaces
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen(2)
        self.sequence = []
        self.players = []
        self.current_turn = 0
        self.turn_lock = Lock()
        self.game_over = False
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.ca = ca
        self.cert = ca.register_user('codemaster', self.public_key)
        self.secure_channels = {}
        self.logger = SecurityLogger('codemaster')
        self.sessions = {}
        self.active_connections: Dict[socket.socket, GameSession] = {}
        self.connection_lock = Lock()
        self.player_count = 0

    def handle_player_disconnect(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        with self.connection_lock:
            if conn in self.active_connections:
                del self.active_connections[conn]
            if conn in self.players:
                self.players.remove(conn)
            self.logger.log_security_event('player_disconnect', f'Player at {addr} disconnected')

    def broadcast_message(self, message: dict, exclude: Optional[socket.socket] = None) -> None:
        for player in self.players:
            if player != exclude:
                try:
                    player.send(json.dumps(message).encode())
                except Exception as e:
                    self.logger.log_error('broadcast_failed', str(e))

    def handshake(self, conn):
        try:
            # Serialize and send certificate
            cert_bytes = self.cert.public_bytes(serialization.Encoding.PEM)
            conn.send(cert_bytes)
            
            # Receive and deserialize client's certificate
            client_cert_bytes = conn.recv(4096)
            client_cert = x509.load_pem_x509_certificate(client_cert_bytes)
            
            if not self.ca.verify_certificate(client_cert):
                return False
            
            # Create new session
            session_id = os.urandom(16).hex()
            session = GameSession(session_id, 'AES')
            self.sessions[conn] = session
            
            # Use CA to distribute session key
            encrypted_keys = self.ca.distribute_keys('codemaster', 'AES', session.key)
            conn.send(json.dumps({'session': session_id, 'keys': encrypted_keys}).encode())
            
            self.logger.log_security_event('handshake_success', f'Session: {session_id}')
            return True
        except Exception as e:
            self.logger.log_error('handshake_failed', str(e))
            return False

    def generate_sequence(self, colors, length=5):
        # Normalize colors to uppercase
        normalized_colors = [color.upper() for color in colors]
        self.sequence = [random.choice(normalized_colors) for _ in range(length)]

    def setup_secure_channel(self, player_id):
        # Generate random key for AES
        key = os.urandom(32)
        cipher_choice = 'AES'
        
        # Get encrypted keys from CA
        encrypted_keys = self.ca.distribute_keys(
            'codemaster',
            cipher_choice,
            key
        )
        
        # Setup secure channel
        self.secure_channels[player_id] = SecureMessage(cipher_choice, key)
        return encrypted_keys[player_id]

    def handle_player(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        try:
            # Assign player number
            player_id = self.player_count
            self.player_count += 1
            print(f"\nPlayer {player_id + 1} connected from {addr}")
            
            if not self.handshake(conn):
                print(f"Player {player_id + 1} handshake failed")
                self.handle_player_disconnect(conn, addr)
                return

            with self.connection_lock:
                self.players.append(conn)
                self.active_connections[conn] = GameSession(os.urandom(16).hex(), 'AES')
            
            # Setup secure communication
            encrypted_key_data = self.setup_secure_channel(player_id)
            conn.send(json.dumps(encrypted_key_data).encode())
            
            print(f"Player {player_id + 1} successfully authenticated")
            if len(self.players) < 2:
                print(f"Waiting for {2 - len(self.players)} more player(s)...")
            else:
                print("\nGame is starting!")
                print(f"Hidden sequence has {len(self.sequence)} colors")
            
            while not self.game_over:
                try:
                    with self.turn_lock:
                        if player_id != self.current_turn:
                            continue
                        
                        # Handle player turn
                        feedback = self.process_player_turn(conn, player_id)
                        if feedback == "WIN":
                            self.end_game(player_id)
                            break
                        
                        self.rotate_turn()
                        self.check_key_rotation(conn)
                except Exception as e:
                    self.logger.log_error('turn_processing_error', str(e))
                    break
                    
        except ConnectionResetError:
            self.logger.log_error('connection_reset', f'Connection reset by {addr}')
        except Exception as e:
            self.logger.log_error('player_handler_error', str(e))
            traceback.print_exc()
        finally:
            self.handle_player_disconnect(conn, addr)

    def process_player_turn(self, conn: socket.socket, player_id: int) -> str:
        encrypted_guess = json.loads(conn.recv(1024).decode())
        guess = self.secure_channels[player_id].decrypt(encrypted_guess)
        feedback = self.check_guess(guess)
        
        self.broadcast_game_state(player_id, guess, feedback)
        return feedback

    def check_key_rotation(self, conn: socket.socket) -> None:
        if self.active_connections[conn].should_rotate_key():
            new_key = self.active_connections[conn].rotate_key()
            encrypted_keys = self.ca.distribute_keys('codemaster', 'AES', new_key)
            self.broadcast_message({'key_rotation': encrypted_keys})

    def end_game(self, winner_id: int) -> None:
        self.game_over = True
        self.broadcast_message({
            'game_over': True,
            'winner': winner_id,
            'sequence': self.sequence
        })

    def check_guess(self, guess):
        # Normalize guesses to uppercase and strip whitespace
        guess_colors = [color.strip().upper() for color in guess.split(',')]
        sequence_colors = [color.upper() for color in self.sequence]
        
        if len(guess_colors) != len(sequence_colors):
            return "Invalid guess length"
        
        exact = 0
        color_matches = 0
        temp_sequence = sequence_colors.copy()
        temp_guess = guess_colors.copy()

        # Check exact matches
        for i in range(len(self.sequence)):
            if temp_guess[i] == temp_sequence[i]:
                exact += 1
                temp_guess[i] = temp_sequence[i] = None

        # Check color matches
        for i in range(len(temp_sequence)):
            if temp_guess[i] is None:
                continue
            for j in range(len(temp_sequence)):
                if temp_sequence[j] and temp_guess[i] == temp_sequence[j]:
                    color_matches += 1
                    temp_sequence[j] = None
                    break

        if exact == len(self.sequence):
            self.game_over = True
            return "WIN"
        
        return f"{exact} exact, {color_matches} color matches"

    def broadcast_game_state(self, player_id: int, guess: str, feedback: str) -> None:
        # Add this missing method
        message = {
            'player': player_id,
            'guess': guess,
            'feedback': feedback
        }
        self.broadcast_message(message)

    def run(self):
        print("\nCodemaster is ready and listening for connections...")
        print(f"Players can connect using: python player.py <player_name>")
        
        while len(self.players) < 2:
            try:
                conn, addr = self.server.accept()
                Thread(target=self.handle_player, args=(conn, addr)).start()
            except Exception as e:
                self.logger.log_error('connection_error', str(e))
                continue
