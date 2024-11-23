# 🎮 Secure Mastermind Game

A secure implementation of the classic Mastermind game with network play and encryption.

## 🎯 Game Overview

The game involves:
- Two players competing to guess a secret color sequence
- A Codemaster (server) that generates and validates guesses
- Secure communication between players and server
- Turn-based gameplay with real-time feedback

## 🎲 How to Play

1. The Codemaster generates a random sequence of 3 unique colors
2. Players take turns guessing the sequence
3. After each guess, players receive feedback:
   - Number of exact matches (right color, right position)
   - Number of color matches (right color, wrong position)
4. First player to guess the sequence correctly wins!

### Available Colors
- RED
- BLUE
- GREEN
- YELLOW
- BLACK
- WHITE

## 🎥 Video showcase

<a href="http://www.youtube.com/watch?feature=player_embedded&v=-GdgR3BcJ5I
" target="_blank"><img src="http://img.youtube.com/vi/-GdgR3BcJ5I/0.jpg" 
alt="No no no no..." /></a>

## 🚀 Getting Started

### Prerequisites
```bash
# Install required packages
pip install cryptography numpy
```

### Starting the Game

1. Start the server (Codemaster):
```bash
python main.py
```

2. Start Player 1:
```bash
python player.py Player1
```

3. Start Player 2:
```bash
python player.py Player2
```

### Making Guesses
- Enter colors as comma-separated values
- Example: `red,blue,green`
- Colors are case-insensitive
- Must enter exactly 3 unique colors

## 📝 Example Game

Server output:
```
Codemaster is ready and listening for connections...
Secret sequence: RED, BLUE, GREEN
```

Player 1 input/output:
```
Enter your guess: black,white,yellow
Feedback: 0 exact matches, 0 color matches

Enter your guess: red,blue,green
Feedback: WIN! Game Over
```

## 🔒 Security Features
- Encrypted communication
- Secure key exchange
- Session management
- Input validation

## 📁 Project Structure
```
mastermind/
├── main.py       # Server startup
├── codemaster.py # Game logic
├── player.py     # Client implementation
├── session.py    # Session handling
├── ciphers.py    # Encryption
└── README.md     # Documentation
```

## ⚠️ Important Notes
- Run the server first before connecting players
- Each game requires exactly 2 players
- Colors must be unique in guesses
- Use commas to separate colors
- Exit with Ctrl+C to stop server/client

## 🐛 Troubleshooting
- If connection fails, ensure server is running
- Check port 25079 is available
- Verify color spelling and format
- Use only listed colors
```

This README provides:
1. Clear game overview
2. Step-by-step setup instructions
3. Usage examples
4. Security features
5. Project structure
6. Troubleshooting tips
7. Important notes for users
