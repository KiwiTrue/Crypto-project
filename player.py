"""
Player module - Implements the game client
"""
import socket
import random  # Add this import for the random player name generation
from typing import Optional, Union
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from ciphers import SecureMessage
from logger import SecurityLogger
from session import GameSession
from secure_protocol import SecureProtocol
import json
import traceback
import sys
import base64  # Add this import at the top of the file

class Player:
    """
    Player class - Handles game client functionality
    
    Attributes:
        name (str): Player name
        client (socket): Client socket connection
        session (GameSession): Current game session
        game_active (bool): Game state flag
    """
    
    def __init__(self, name: str, host: str = 'localhost', port: int = 25079):
        self.name = name
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.settimeout(30)  # Increased timeout to 30 seconds
        try:
            self.client.connect((host, port))
        except socket.error as e:
            raise ConnectionError(f"Failed to connect to server: {str(e)}")
        self.game_active = True
        self.private_key, self.public_key = SecureProtocol.generate_keypair(f"player_{name}")
        self.secure_channel: Optional[SecureMessage] = None
        self.logger = SecurityLogger(f'player_{name}')
        self.session: Optional[GameSession] = None
        self.on_message = lambda x: print(f"Server: {x}")  # Add callback
        self.valid_colors = ["RED", "BLUE", "GREEN", "YELLOW", "BLACK", "WHITE"]

    def handle_key_rotation(self, encrypted_key_data: dict) -> bool:
        try:
            # Decrypt new key using private key
            new_key = self.private_key.decrypt(
                encrypted_key_data['key'],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Update secure channel with new key
            self.secure_channel = SecureMessage(encrypted_key_data['cipher'], new_key)
            self.logger.log_security_event('key_rotation_success', 
                                         f'Session: {self.session.session_id}')
            return True
        except Exception as e:
            self.logger.log_error('key_rotation_failed', str(e))
            return False

    def process_server_response(self, response: str) -> bool:
        try:
            data = json.loads(response)
            if 'game_over' in data:
                print(f"\n{data['message']}")
                return False
            elif 'feedback' in data:
                try:
                    # Properly decrypt the feedback message
                    encrypted_feedback = data['feedback']
                    decrypted_feedback = self.secure_channel.decrypt(encrypted_feedback)
                    print(f"\nFeedback: {decrypted_feedback}")
                except Exception as e:
                    print(f"\nServer: {response}")
                return "wins" not in response
            return True
        except json.JSONDecodeError:
            print(f"\nServer: {response}")
            return "wins" not in response

    def send_guess(self, guess: str) -> bool:
        try:
            if self.secure_channel:
                # Additional validation for guess format
                colors = [c.strip().upper() for c in guess.split(',')]
                if len(colors) != 3:
                    print("Please enter exactly 3 colors, separated by commas")
                    return True
                
                # Validate colors
                if not all(color in self.valid_colors for color in colors):
                    print(f"Invalid colors! Please use only: {', '.join(self.valid_colors)}")
                    return True
                    
                # Normalize guess format
                normalized_guess = ','.join(colors)
                
                try:
                    # Encrypt and send guess
                    padded_guess = GameSession.pad_data(normalized_guess.encode())
                    secure_msg = self.secure_channel.encrypt(padded_guess)
                    
                    # Convert bytes to base64 for JSON serialization
                    if isinstance(secure_msg.get('data'), bytes):
                        secure_msg['data'] = base64.b64encode(secure_msg['data']).decode('utf-8')
                    if isinstance(secure_msg.get('mac'), bytes):
                        secure_msg['mac'] = base64.b64encode(secure_msg['mac']).decode('utf-8')
                    
                    self.client.send(json.dumps(secure_msg).encode())
                    
                    # Wait for response with timeout
                    response = self.client.recv(1024).decode()
                    if not response:
                        print("\nLost connection to server.")
                        return False
                        
                    return self.process_server_response(response)
                    
                except socket.timeout:
                    print("\nWaiting for your turn...")
                    return True
                except (ConnectionError, BrokenPipeError) as e:
                    print(f"\nConnection error: {str(e)}")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.log_error('communication_error', str(e))
            traceback.print_exc()
            return False

    def handshake(self) -> bool:
        """
        Performs secure handshake with server
        
        Returns:
            bool: True if handshake successful, False otherwise
        """
        try:
            # Share supported ciphers
            supported_ciphers = SecureProtocol.SUPPORTED_CIPHERS
            self.client.send(json.dumps(supported_ciphers).encode())
            
            # Export and send public key in proper PEM format
            pem_key = SecureProtocol.export_public_key(self.public_key)
            self.client.send(pem_key)  # Send raw PEM bytes
            
            # Receive server's public key
            server_public_key_bytes = self.client.recv(4096)
            server_public_key = serialization.load_pem_public_key(
                server_public_key_bytes,
                backend=None
            )
            
            # Receive cipher choice and encrypted session key
            response = json.loads(self.client.recv(1024).decode())
            cipher_type = response['cipher']
            # Decode base64 key
            encrypted_key = base64.b64decode(response['key'])
            
            # Decrypt session key and establish secure channel
            session_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            self.secure_channel = SecureMessage(cipher_type, session_key)
            return True
            
        except Exception as e:
            self.logger.log_error('handshake_failed', str(e))  # Changed from error to log_error
            traceback.print_exc()
            return False

    def establish_secure_channel(self, encrypted_key_data):
        cipher_type = encrypted_key_data['cipher']
        encrypted_key = encrypted_key_data['key']
        
        key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        self.secure_channel = SecureMessage(cipher_type, key)

    def play(self):
        try:
            if not self.handshake():
                self.logger.log_error('connection_failed', 'Failed to establish secure connection')
                return

            print(f"Player {self.name} is ready.")
            print("Available colors: RED, BLUE, GREEN, YELLOW, BLACK, WHITE")
            print("Enter your guess as comma-separated colors (e.g., red,blue,green)")
            print("Select exactly 3 colors from the available colors")
            
            while self.game_active:
                try:
                    guess = input("Enter your guess (comma-separated colors): ")
                    if not self.send_guess(guess):
                        print("\nGame ended.")
                        break
                except KeyboardInterrupt:
                    print("\nGame terminated by user")
                    break
                except Exception as e:
                    self.logger.log_error('gameplay_error', str(e))
                    print(f"\nError during gameplay: {str(e)}")
                    break
        finally:
            self.client.close()
            self.logger.log_security_event('session_end', 
                                         f'Player {self.name} disconnected')

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python player.py <player_name>")
        sys.exit(1)
        
    player_name = sys.argv[1]
    print(f"\nConnecting to game server as {player_name}...")
    
    try:
        player = Player(player_name)  # Remove CA parameter
        player.play()
    except ConnectionRefusedError:
        print("Could not connect to game server. Make sure the server is running.")
    except Exception as e:
        print(f"Error: {str(e)}")
        traceback.print_exc()
