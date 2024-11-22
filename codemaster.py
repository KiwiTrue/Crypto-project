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
        
        # Game state
        self.colors = ["RED", "BLUE", "GREEN", "YELLOW", "BLACK", "WHITE"]
        self.sequence = []  # Initialize empty sequence
        self.players = []
        self.current_turn = 0
        self.game_over = False
        
        # Generate sequence after initialization
        self.sequence = self.generate_sequence()
        
        # Security setup (simplified)
        self.private_key, self.public_key = SecureProtocol.generate_keypair("codemaster")
        self.secure_channels = {}
        
        print(f"Secret sequence: {self.sequence}")

    def generate_sequence(self, length=5) -> List[str]:
        """Generate random color sequence of specified length"""
        if len(self.colors) < length:
            raise ValueError(f"Need at least {length} colors")
        # Use random.sample instead of choices to ensure unique colors
        return random.sample(self.colors, length)

    def check_guess(self, guess: list) -> str:
        """Task 3.2: Compare guess with sequence and provide feedback"""
        if len(guess) != len(self.sequence):
            return "Invalid guess length"
            
        exact = sum(1 for g, s in zip(guess, self.sequence) if g == s)
        # Count color matches (right color, wrong position)
        color_matches = sum(min(guess.count(c), self.sequence.count(c)) for c in set(guess)) - exact
        
        return "WIN" if exact == len(self.sequence) else f"{exact} exact, {color_matches} color matches"

    def handle_player(self, conn: socket.socket, player_id: int):
        try:
            # Setup secure channel
            self.setup_secure_connection(conn, player_id)
            
            while not self.game_over:
                if player_id != self.current_turn:
                    continue
                
                # Process guess
                guess = self.receive_guess(conn, player_id)
                if not guess:
                    break
                
                # Send feedback
                feedback = self.check_guess(guess)
                self.send_feedback(conn, player_id, feedback)
                
                if feedback == "WIN":
                    self.broadcast_winner(player_id)
                    break
                
                self.current_turn = (self.current_turn + 1) % len(self.players)
                
        finally:
            if conn in self.players:
                self.players.remove(conn)

    def run(self):
        print("\nWaiting for players...")
        while len(self.players) < 2:
            conn, _ = self.server.accept()
            self.players.append(conn)
            Thread(target=self.handle_player, args=(conn, len(self.players)-1)).start()
