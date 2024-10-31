# Player.py

import socket
from CryptoFunctions import encrypt, decrypt
from CertificationAuthority import CertificationAuthority
import tkinter as tk
from tkinter import simpledialog, messagebox
import struct
import json

class Player:
    def __init__(self, name, host='localhost', port=5555):
        self.name = name
        self.host = host
        self.port = port
        self.private_key, self.public_key = CertificationAuthority.generate_keys()
        self.certificate = CertificationAuthority.certify_user(self.public_key)
        self.server_public_key = None
        self.client = None

    def connect_to_server(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client.connect((self.host, self.port))
            print(f'{self.name} connected to Codemaster.')
            # Exchange certificates and obtain server's public key
            self.exchange_certificates()
        except ConnectionRefusedError:
            print("Connection to server failed. Ensure the server is running and try again.")

    def exchange_certificates(self):
        # Send own certificate with length
        cert_len = len(self.certificate)
        self.client.sendall(struct.pack('>I', cert_len))
        self.client.sendall(self.certificate)
        # Receive server's certificate length
        data = self.receive_all(4)
        if not data:
            print("Failed to receive certificate length.")
            self.client.close()
            return
        server_cert_len = struct.unpack('>I', data)[0]
        # Receive server's certificate
        server_cert = self.receive_all(server_cert_len)
        self.server_public_key = CertificationAuthority.validate_certificate(server_cert)
        if not self.server_public_key:
            print("Failed to validate server's certificate.")
            self.client.close()
            return

    def make_guess(self, guess):
        guess_json = json.dumps(guess)
        encrypted_guess = encrypt(guess_json, self.server_public_key, cipher='rsa')
        # Send encrypted guess with length
        msg_len = len(encrypted_guess)
        self.client.sendall(struct.pack('>I', msg_len))
        self.client.sendall(encrypted_guess)

    def receive_feedback(self):
        # Receive feedback length
        data = self.receive_all(4)
        if not data:
            print("Failed to receive feedback length.")
            self.client.close()
            return
        feedback_len = struct.unpack('>I', data)[0]
        # Receive encrypted feedback
        encrypted_feedback = self.receive_all(feedback_len)
        feedback_json = decrypt(encrypted_feedback, self.private_key, cipher='rsa')
        feedback = json.loads(feedback_json)
        return feedback

    def receive_all(self, n):
        data = b''
        while len(data) < n:
            packet = self.client.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def send_encrypted_message(self, message):
        return encrypt(message, self.server_public_key, cipher='rsa')

    def receive_encrypted_message(self, encrypted_message):
        return decrypt(encrypted_message, self.private_key, cipher='rsa')

    def play_game(self):
        root = tk.Tk()
        root.withdraw()  # Hide the root window

        while True:
            guess = simpledialog.askstring("Input", "Enter your guess (e.g., red green blue yellow):")
            if guess:
                guess_list = guess.split()
                self.make_guess(guess_list)
                feedback = self.receive_feedback()
                messagebox.showinfo("Feedback", f"Exact matches: {feedback['exact']}, Color matches: {feedback['color']}")
                if feedback.get('win'):
                    messagebox.showinfo("Result", "Congratulations! You guessed the correct sequence.")
                    break
                elif feedback.get('game_over'):
                    messagebox.showinfo("Result", "Game over.")
                    break
            else:
                break

if __name__ == '__main__':
    player = Player(name='Player1')
    player.connect_to_server()
    player.play_game()
