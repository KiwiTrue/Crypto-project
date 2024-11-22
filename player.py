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

    def send_guess(self, guess: str) -> bool:
        try:
            encrypted_guess = self.secure_channel.encrypt(guess)
            self.client.send(json.dumps(encrypted_guess).encode())
            
            response = json.loads(self.client.recv(1024).decode())
            feedback = self.secure_channel.decrypt(response)
            
            print(f"Server: {feedback}")
            return "WIN" not in feedback
            
        except Exception as e:
            print(f"Error: {e}")
            return False

    def play(self):
        try:
            self.connect()
            print("\nConnected to game server")
            print("Available colors: RED, BLUE, GREEN, YELLOW, BLACK, WHITE")
            print("Enter 5 comma-separated colors")
            
            while self.game_active:
                guess = input("\nYour guess: ")
                if not self.send_guess(guess):
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
