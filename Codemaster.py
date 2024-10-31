
# Codemaster.py

import socket
import threading
from CryptoFunctions import encrypt, decrypt
from GameLogic import generate_random_sequence, evaluate_guess
from CertificationAuthority import CertificationAuthority

class Codemaster:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.clients = []
        self.secret_sequence = self.generate_sequence()
        self.ca = CertificationAuthority()
        self.private_key, self.public_key = self.ca.generate_keys()
        self.certificate = self.ca.certify_user(self.public_key)

    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen()
        print('Codemaster server started.')
        while True:
            client_socket, addr = server.accept()
            print(f'Player connected from {addr}')
            self.clients.append(client_socket)
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def generate_sequence(self):
        colors = ['red', 'green', 'blue', 'yellow', 'orange', 'purple']
        return generate_random_sequence(colors, 4)

    def handle_client(self, client_socket):
        while True:
            encrypted_guess = client_socket.recv(1024)
            guess = self.receive_encrypted_message(encrypted_guess)
            feedback = self.process_guess(guess)
            encrypted_feedback = self.send_encrypted_message(feedback)
            client_socket.sendall(encrypted_feedback)
            if feedback['win']:
                self.declare_winner(client_socket)
                break

    def process_guess(self, guess):
        exact, color = evaluate_guess(self.secret_sequence, guess)
        feedback = {'exact': exact, 'color': color, 'win': exact == len(self.secret_sequence)}
        return feedback

    def declare_winner(self, winner_socket):
        for client in self.clients:
            if client == winner_socket:
                message = 'You win!'
            else:
                message = 'You lose!'
            encrypted_message = self.send_encrypted_message(message)
            client.sendall(encrypted_message)
        print('Game over.')
        self.reset_game()

    def send_encrypted_message(self, message):
        return encrypt(message, self.private_key, cipher='rsa')

    def receive_encrypted_message(self, encrypted_message):
        return decrypt(encrypted_message, self.private_key, cipher='rsa')

    def reset_game(self):
        self.secret_sequence = self.generate_sequence()
        # Optionally reset other game states

if __name__ == '__main__':
    codemaster = Codemaster()
    codemaster.start_server()