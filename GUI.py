# GUI.py

import tkinter as tk
from Player import Player
import threading

class GameGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('Mastermind Game')
        self.player = None
        self.create_start_screen()

    def create_start_screen(self):
        self.name_label = tk.Label(self.root, text='Enter your name:')
        self.name_label.pack()
        self.name_entry = tk.Entry(self.root)
        self.name_entry.pack()
        self.start_button = tk.Button(self.root, text='Start Game', command=self.start_game)
        self.start_button.pack()

    def start_game(self):
        name = self.name_entry.get()
        self.player = Player(name=name)
        self.player.connect_to_server()
        self.name_label.destroy()
        self.name_entry.destroy()
        self.start_button.destroy()
        self.create_game_screen()
        threading.Thread(target=self.receive_feedback).start()

    def create_game_screen(self):
        self.guess_label = tk.Label(self.root, text='Enter your guess:')
        self.guess_label.pack()
        self.guess_entry = tk.Entry(self.root)
        self.guess_entry.pack()
        self.submit_button = tk.Button(self.root, text='Submit Guess', command=self.submit_guess)
        self.submit_button.pack()
        self.feedback_label = tk.Label(self.root, text='')
        self.feedback_label.pack()

    def submit_guess(self):
        guess_text = self.guess_entry.get()
        guess = guess_text.strip().split()
        self.player.make_guess(guess)
        self.guess_entry.delete(0, tk.END)

    def receive_feedback(self):
        while True:
            feedback = self.player.receive_feedback()
            self.update_feedback(feedback)
            if feedback.get('win') or feedback.get('game_over'):
                break

    def update_feedback(self, feedback):
        text = f"Exact matches: {feedback['exact']}, Color matches: {feedback['color']}"
        self.feedback_label.config(text=text)

    def run(self):
        self.root.mainloop()

if __name__ == '__main__':
    gui = GameGUI()
    gui.run()