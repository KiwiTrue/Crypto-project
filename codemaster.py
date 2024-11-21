import socket
from typing import List, Dict, Optional, Tuple
from threading import Lock, Thread
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from session import GameSession
from logger import SecurityLogger
from ciphers import SecureMessage
from secure_protocol import SecureProtocol
import traceback
import json
import os
import base64
import random

"""
Codemaster module - Implements the game server and game logic
"""

class Codemaster:
    """
    Codemaster class - Manages the game server and game state
    
    Attributes:
        sequence (List[str]): Hidden color sequence for players to guess
        players (List[socket]): Connected player sockets
        current_turn (int): Current player's turn
        game_over (bool): Game state flag
    """
    
    def __init__(self, host='0.0.0.0', port=12345):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen(2)
        # Basic setup
        self.sequence = []
        self.players = []
        self.current_turn = 0
        self.player_count = 0
        self.game_over = False
        
        # Thread safety
        self.turn_lock = Lock()
        self.connection_lock = Lock()
        
        # Security components
        self.private_key, self.public_key = SecureProtocol.generate_keypair("codemaster")
        self.secure_channels = {}
        self.active_connections = {}
        self.logger = SecurityLogger('codemaster')

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

    def generate_sequence(self, colors, length=5):
        # Normalize colors to uppercase
        normalized_colors = [color.upper() for color in colors]
        # Use random.sample to ensure no repeats
        self.sequence = random.sample(normalized_colors, length)

    def setup_secure_channel(self, conn: socket.socket, player_id: int, player_public_key: rsa.RSAPublicKey) -> dict:
        try:
            # Generate session key
            cipher_type = 'AES'
            session_key = SecureProtocol.generate_session_key(cipher_type)
            
            # Encrypt session key for player
            encrypted_key = player_public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Create secure channel
            self.secure_channels[player_id] = SecureMessage(cipher_type, session_key)
            
            return {
                'cipher': cipher_type,
                'key': base64.b64encode(encrypted_key).decode('utf-8')
            }
        except Exception as e:
            self.logger.log_error('secure_channel_setup_failed', str(e))
            raise

    def handle_player(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        try:
            player_id = self.player_count
            self.player_count += 1
            print(f"\nPlayer {player_id + 1} connected from {addr}")
            
            # Receive client's ciphers first
            client_ciphers = json.loads(conn.recv(1024).decode())
            
            # Receive and load client's public key
            client_key_data = conn.recv(4096)
            try:
                client_public_key = serialization.load_pem_public_key(
                    client_key_data,
                    backend=None
                )
            except ValueError as e:
                self.logger.log_error('key_load_error', f'Invalid key format received: {str(e)}')
                raise
            
            # Send our public key in PEM format
            conn.send(SecureProtocol.export_public_key(self.public_key))
            
            with self.connection_lock:
                self.players.append(conn)
                self.active_connections[conn] = GameSession(os.urandom(16).hex(), 'AES')
            
            # Setup secure communication with client's public key
            encrypted_key_data = self.setup_secure_channel(conn, player_id, client_public_key)
            conn.send(json.dumps(encrypted_key_data).encode())
            
            print(f"Player {player_id + 1} successfully authenticated")
            print(f"Current sequence: {', '.join(self.sequence)}")  # Add this line to show sequence
            
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
                        
                        feedback = self.process_player_turn(conn, player_id)
                        if feedback == "WIN":
                            self.game_over = True
                            self.broadcast_message({
                                'game_over': True,
                                'winner': player_id,
                                'sequence': self.sequence
                            })
                            break
                        
                        # Ensure response is sent before changing turn
                        conn.send(json.dumps({'feedback': feedback}).encode())
                        self.current_turn = (self.current_turn + 1) % len(self.players)
                except socket.error as e:
                    self.logger.log_error('socket_error', str(e))
                    break
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
        try:
            # Receive and decrypt guess
            encrypted_data = conn.recv(1024).decode()
            if not encrypted_data:
                return "Invalid guess"
                
            encrypted_guess = json.loads(encrypted_data)
            if 'data' in encrypted_guess:
                # Convert base64 back to bytes
                encrypted_guess['data'] = base64.b64decode(encrypted_guess['data'])
            if 'mac' in encrypted_guess:
                encrypted_guess['mac'] = base64.b64decode(encrypted_guess['mac'])
                
            # Get the decrypted guess and handle both string and bytes types
            guess = self.secure_channels[player_id].decrypt(encrypted_guess)
            guess_str = guess if isinstance(guess, str) else guess.decode()
            feedback = self.check_guess(guess_str.strip())
            
            # Pad feedback before encryption
            feedback_padded = GameSession.pad_data(feedback.encode())
            secure_msg = self.secure_channels[player_id].encrypt(feedback_padded)
            
            if isinstance(secure_msg.get('data'), bytes):
                secure_msg['data'] = base64.b64encode(secure_msg['data']).decode('utf-8')
            if isinstance(secure_msg.get('mac'), bytes):
                secure_msg['mac'] = base64.b64encode(secure_msg['mac']).decode('utf-8')
                
            # Send response back to the player
            response = json.dumps({'feedback': secure_msg})
            conn.send(response.encode())
            
            return feedback
            
        except Exception as e:
            self.logger.log_error('turn_processing_error', str(e))
            traceback.print_exc()
            return "Error processing turn"

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

    def handle_player_turn(self, conn: socket.socket, player_id: int) -> None:
        if player_id != self.current_player:
            return {'error': 'Not your turn'}
            
        # Process turn
        result = self.process_player_turn(conn, player_id)
        
        # Update turn
        self.current_player = (self.current_player + 1) % self.total_players
        
        return result

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

    def handle_handshake(self, conn: socket.socket) -> bool:
        """
        Handles secure connection handshake with a player
        
        Args:
            conn: Player's socket connection
            
        Returns:
            bool: True if handshake successful, False otherwise
        """
        try:
            # Receive supported ciphers
            client_ciphers = json.loads(conn.recv(1024).decode())
            
            # Exchange public keys
            client_public_key_bytes = conn.recv(4096)
            client_public_key = serialization.load_pem_public_key(
                client_public_key_bytes,
                backend=None
            )
            conn.send(SecureProtocol.export_public_key(self.public_key))
            
            # Select cipher and generate session key
            cipher_type = SecureProtocol.negotiate_cipher(
                SecureProtocol.SUPPORTED_CIPHERS,
                client_ciphers
            )
            session_key = SecureProtocol.generate_session_key(cipher_type)
            
            # Encrypt and send session key
            encrypted_key = client_public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Convert bytes to base64 before sending
            conn.send(json.dumps({
                'cipher': cipher_type,
                'key': base64.b64encode(encrypted_key).decode('utf-8')
            }).encode())
            
            # Setup secure channel
            self.secure_channels[conn] = SecureMessage(cipher_type, session_key)
            return True
            
        except Exception as e:
            self.logger.log_error('handshake_failed', str(e))  # Changed from error to log_error
            traceback.print_exc()
            return False
