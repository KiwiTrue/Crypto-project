import socket
import random  # Add this import for the random player name generation
from typing import Optional, Union
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from ciphers import SecureMessage
from logger import SecurityLogger
from session import GameSession
from CA import CertificationAuthority
import json
import traceback
import sys

class Player:
    def __init__(self, name: str, ca, host: str = 'localhost', port: int = 12345):
        self.name = name
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.settimeout(10)  # Add timeout
        try:
            self.client.connect((host, port))
        except socket.error as e:
            raise ConnectionError(f"Failed to connect to server: {str(e)}")
        self.game_active = True
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.ca = ca
        self.cert = ca.register_user(name, self.public_key)
        self.secure_channel: Optional[SecureMessage] = None
        self.logger = SecurityLogger(f'player_{name}')
        self.session: Optional[GameSession] = None
        self.on_message = lambda x: print(f"Server: {x}")  # Add callback

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
            if 'key_rotation' in data:
                return self.handle_key_rotation(data['key_rotation'])
            elif 'feedback' in data:
                feedback = self.secure_channel.decrypt(data['feedback'])
                self.on_message(feedback)  # Use callback instead of print
                return "Game Over" not in feedback
            return True
        except json.JSONDecodeError:
            print(f"Server: {response}")
            return "Game Over" not in response

    def send_guess(self, guess: str) -> bool:
        try:
            if self.secure_channel:
                # Normalize guess format
                normalized_guess = ','.join(
                    color.strip().upper() 
                    for color in guess.split(',')
                )
                # Pad and encrypt guess
                padded_guess = GameSession.pad_data(normalized_guess.encode())
                secure_msg = self.secure_channel.encrypt(padded_guess)
                self.client.send(json.dumps(secure_msg).encode())
                
                # Receive and process response
                response = self.client.recv(1024).decode()
                return self.process_server_response(response)
            else:
                self.logger.log_error('secure_channel_missing', 'No secure channel established')
                return False
        except Exception as e:
            self.logger.log_error('communication_error', str(e))
            traceback.print_exc()
            return False

    def handshake(self) -> bool:
        try:
            # Receive and deserialize server's certificate
            server_cert_bytes = self.client.recv(4096)
            server_cert = x509.load_pem_x509_certificate(server_cert_bytes)
            
            if not self.ca.verify_certificate(server_cert):
                return False
                
            # Serialize and send our certificate
            cert_bytes = self.cert.public_bytes(serialization.Encoding.PEM)
            self.client.send(cert_bytes)
            
            # Receive encrypted session key
            encrypted_key_data = json.loads(self.client.recv(1024).decode())
            self.establish_secure_channel(encrypted_key_data)
            
            # Receive session data
            session_data = json.loads(self.client.recv(1024).decode())
            self.session = GameSession(session_data['session'], 'AES')
            self.establish_secure_channel(session_data['keys'])
            
            self.logger.log_security_event('handshake_success', 
                                         f'Session: {self.session.session_id}')
            return True
        except Exception as e:
            self.logger.log_error('handshake_failed', str(e))
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
            print("Enter your guess as comma-separated colors (e.g., red,blue,green,yellow,black)")
            
            while self.game_active:
                try:
                    guess = input("Enter your guess (comma-separated colors): ")
                    if not self.send_guess(guess):
                        break
                except KeyboardInterrupt:
                    print("\nGame terminated by user")
                    break
                except Exception as e:
                    self.logger.log_error('gameplay_error', str(e))
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
        ca = CertificationAuthority()
        player = Player(player_name, ca)
        player.play()
    except ConnectionRefusedError:
        print("Could not connect to game server. Make sure the server is running.")
    except Exception as e:
        print(f"Error: {str(e)}")
        traceback.print_exc()
