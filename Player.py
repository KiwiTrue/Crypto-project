# Player.py

import socket
from CryptoFunctions import encrypt, decrypt
from CertificationAuthority import CertificationAuthority

class Player:
    def __init__(self, name, host='localhost', port=5555):
        self.name = name
        self.host = host
        self.port = port
        self.ca = CertificationAuthority()
        self.private_key, self.public_key = self.ca.generate_keys()
        self.certificate = self.ca.certify_user(self.public_key)
        self.server_public_key = None

    def connect_to_server(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))
        print(f'{self.name} connected to Codemaster.')
        # Exchange certificates and obtain server's public key
        self.exchange_certificates()

    def exchange_certificates(self):
        # Send own certificate
        self.client.sendall(self.certificate)
        # Receive server's certificate
        server_cert = self.client.recv(1024)
        self.server_public_key = self.ca.validate_certificate(server_cert)

    def make_guess(self, guess):
        encrypted_guess = self.send_encrypted_message(guess)
        self.client.sendall(encrypted_guess)

    def receive_feedback(self):
        encrypted_feedback = self.client.recv(1024)
        feedback = self.receive_encrypted_message(encrypted_feedback)
        return feedback

    def send_encrypted_message(self, message):
        return encrypt(message, self.server_public_key, cipher='rsa')

    def receive_encrypted_message(self, encrypted_message):
        return decrypt(encrypted_message, self.private_key, cipher='rsa')

    def play_game(self):
        while True:
            guess = input('Enter your guess (e.g., red green blue yellow): ').split()
            self.make_guess(guess)
            feedback = self.receive_feedback()
            print(f"Exact matches: {feedback['exact']}, Color matches: {feedback['color']}")
            if feedback.get('win'):
                print('Congratulations! You guessed the correct sequence.')
                break
            elif feedback.get('game_over'):
                print('Game over.')
                break

if __name__ == '__main__':
    player = Player(name='Player1')
    player.connect_to_server()
    player.play_game()