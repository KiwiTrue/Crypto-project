# Codemaster.py

import socket
import threading
import atexit
import struct
import json
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
        self.private_key, self.public_key = CertificationAuthority.generate_keys()
        self.certificate = CertificationAuthority.certify_user(self.public_key)
        self.running = True
        atexit.register(self.stop_server)

    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen()
        print('Codemaster server started.')
        while self.running:
            try:
                client_socket, addr = server.accept()
                print(f'Player connected from {addr}')
                self.clients.append(client_socket)
                threading.Thread(target=self.handle_client, args=(client_socket,)).start()
            except OSError:
                break

    def stop_server(self):
        self.running = False
        for client in self.clients:
            client.close()
        print('Codemaster server stopped.')

    def generate_sequence(self):
        colors = ['red', 'green', 'blue', 'yellow', 'orange', 'purple']
        return generate_random_sequence(colors, 4)

    def handle_client(self, client_socket):
        # Receive client's certificate length
        data = self.receive_all(client_socket, 4)
        if not data:
            client_socket.close()
            return
        client_cert_len = struct.unpack('>I', data)[0]
        # Receive client's certificate
        client_cert = self.receive_all(client_socket, client_cert_len)
        if not client_cert:
            client_socket.close()
            return
        # Send own certificate with length
        cert_len = len(self.certificate)
        client_socket.sendall(struct.pack('>I', cert_len))
        client_socket.sendall(self.certificate)
        # Validate client's certificate
        client_public_key = CertificationAuthority.validate_certificate(client_cert)
        if not client_public_key:
            print("Failed to validate client's certificate.")
            client_socket.close()
            return
        while self.running:
            try:
                # Receive message length
                data = self.receive_all(client_socket, 4)
                if not data:
                    break
                msg_len = struct.unpack('>I', data)[0]
                # Receive encrypted guess
                encrypted_guess = self.receive_all(client_socket, msg_len)
                guess_json = decrypt(encrypted_guess, self.private_key, cipher='rsa')
                guess = json.loads(guess_json)
                feedback = self.process_guess(guess)
                feedback_json = json.dumps(feedback)
                encrypted_feedback = encrypt(feedback_json, client_public_key, cipher='rsa')
                # Send feedback with length
                feedback_len = len(encrypted_feedback)
                client_socket.sendall(struct.pack('>I', feedback_len))
                client_socket.sendall(encrypted_feedback)
                if feedback['win']:
                    self.declare_winner(client_socket)
                    break
            except Exception as e:
                print(f"Error handling client: {e}")
                break
        client_socket.close()

    def receive_all(self, sock, n):
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

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
