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
    
    def __init__(self, name: str):
        self.name = name
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key, self.public_key = SecureProtocol.generate_keypair(f"player_{name}")
        self.secure_channel = None
        self.game_active = True
        self.colors = ["RED", "BLUE", "GREEN", "YELLOW", "BLACK", "WHITE"]

    def validate_guess(self, guess: str) -> list:
        """Validate and format guess"""
        colors = [c.strip().upper() for c in guess.split(',')]
        if len(colors) != 5 or not all(c in self.colors for c in colors):
            return None
        return colors

    def connect(self, host='localhost', port=12345):
        self.client.connect((host, port))
        
        # Send public key
        self.client.send(self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
        # Receive server's public key
        server_public_key = serialization.load_pem_public_key(self.client.recv(4096))
        
        # Receive encrypted session key
        encrypted_key = self.client.recv(4096)
        session_key = self.private_key.decrypt(encrypted_key, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
        
        self.secure_channel = SecureMessage(SecureProtocol.CIPHER_TYPE, session_key)

    def send_guess(self, colors: list) -> bool:
        """Send guess and receive feedback"""
        try:
            # Create message
            message = ','.join(colors)
            
            # Encrypt message
            encrypted = self.secure_channel.encrypt(message)
            
            # Convert bytes data to base64 for JSON
            encrypted['data'] = base64.b64encode(encrypted['data']).decode('utf-8')
            encrypted['mac'] = base64.b64encode(encrypted['mac']).decode('utf-8')
            encrypted['iv'] = base64.b64encode(encrypted['iv']).decode('utf-8')
            
            # Send encrypted message
            self.client.send(json.dumps(encrypted).encode())
            
            # Receive and process response
            response_data = self.client.recv(1024).decode()
            response = json.loads(response_data)
            
            # Convert base64 back to bytes
            response['data'] = base64.b64decode(response['data'])
            response['mac'] = base64.b64decode(response['mac'])
            response['iv'] = base64.b64decode(response['iv'])
            
            # Decrypt response
            feedback = self.secure_channel.decrypt(response)
            print(f"Feedback: {feedback}")
            return "WIN" not in feedback
            
        except Exception as e:
            print(f"Error: {e}")
            traceback.print_exc()
            return False

    def play(self):
        try:
            # Connect and setup secure channel
            self.connect()
            print(f"\nPlayer {self.name} connected to game")
            print("Colors:", ", ".join(self.colors))
            print("Enter 5 comma-separated colors (e.g., RED,BLUE,GREEN,YELLOW,BLACK)")
            
            while self.game_active:
                guess = input("\nYour guess: ")
                colors = self.validate_guess(guess)
                if not colors:
                    print("Invalid guess! Use 5 valid colors.")
                    continue
                
                if not self.send_guess(colors):
                    break
        finally:
            self.client.close()

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
