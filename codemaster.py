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
from datetime import datetime

"""
Codemaster module - Implements the game server and game logic
"""

class Codemaster:
    def __init__(self, host='0.0.0.0', port=12345):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen(2)
        
        # Basic game state
        self.colors = ["RED", "BLUE", "GREEN", "YELLOW", "BLACK", "WHITE"]
        self.sequence = random.sample(self.colors, 5)
        self.players = []
        self.current_turn = 0
        self.game_over = False
        
        # Security
        self.private_key, self.public_key = SecureProtocol.generate_keypair("codemaster")
        self.secure_channels = {}
        
        print(f"Secret sequence: {self.sequence}")  # For debugging

    def handle_player(self, conn: socket.socket, player_id: int) -> None:
        try:
            # Basic handshake
            client_public_key = serialization.load_pem_public_key(conn.recv(4096))
            conn.send(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            
            # Setup secure channel
            session_key = SecureProtocol.generate_session_key()
            encrypted_key = client_public_key.encrypt(session_key, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
            conn.send(encrypted_key)
            
            self.secure_channels[player_id] = SecureMessage(SecureProtocol.CIPHER_TYPE, session_key)
            
            # Game loop
            while not self.game_over:
                if player_id != self.current_turn:
                    continue
                    
                # Handle guess
                guess = self.receive_guess(conn, player_id)
                if not guess:
                    break
                    
                feedback = self.check_guess(guess)
                self.send_feedback(conn, player_id, feedback)
                
                if feedback == "WIN":
                    self.game_over = True
                else:
                    self.current_turn = (self.current_turn + 1) % len(self.players)
                    
        except Exception as e:
            print(f"Player {player_id} error: {e}")
        finally:
            if conn in self.players:
                self.players.remove(conn)

    def receive_guess(self, conn: socket.socket, player_id: int) -> Optional[List[str]]:
        try:
            encrypted_data = json.loads(conn.recv(1024).decode())
            guess = self.secure_channels[player_id].decrypt(encrypted_data)
            return [c.strip().upper() for c in guess.split(',')]
        except:
            return None

    def send_feedback(self, conn: socket.socket, player_id: int, feedback: str) -> None:
        try:
            encrypted_feedback = self.secure_channels[player_id].encrypt(feedback)
            conn.send(json.dumps(encrypted_feedback).encode())
        except:
            pass

    def check_guess(self, guess: List[str]) -> str:
        if len(guess) != len(self.sequence):
            return "Invalid guess length"
            
        exact = sum(1 for i in range(len(self.sequence)) if guess[i] == self.sequence[i])
        colors = sum(1 for g in guess if g in self.sequence) - exact
        
        return "WIN" if exact == len(self.sequence) else f"{exact} exact, {colors} color matches"

    def run(self):
        print("\nWaiting for players...")
        while len(self.players) < 2:
            conn, addr = self.server.accept()
            self.players.append(conn)
            Thread(target=self.handle_player, args=(conn, len(self.players)-1)).start()
