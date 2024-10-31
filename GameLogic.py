# GameLogic.py

import random

def generate_random_sequence(colors, length):
    return random.sample(colors, length)

def evaluate_guess(sequence, guess):
    exact = sum(a == b for a, b in zip(sequence, guess))
    color = sum(min(sequence.count(c), guess.count(c)) for c in set(guess)) - exact
    return exact, color

def check_for_win(sequence, guess):
    return sequence == guess