
# 🎮 Secure Mastermind Game

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

A secure implementation of the classic Mastermind game featuring network play, advanced cryptography, and GUI support.

</div>

---

## ✨ Features

### 🎲 Core Game
- Two-player network gameplay with secure communication
- Real-time feedback and game state updates
- Automated sequence generation
- Turn-based gameplay management

### 🔒 Security Features
<details>
<summary>Click to expand</summary>

#### Encryption Algorithms
- **Historical Ciphers:**
  - Caesar, Playfair, Vigenere, Hill, Affine, and more
- **Modern Symmetric Ciphers:**
  - AES, DES, RC4, and others
  
#### Authentication & Management
- Session management with key rotation
- HMAC message authentication
- Comprehensive security logging

</details>

### 🖥️ User Interface
- Command Line Interface (CLI)
- Graphical User Interface (GUI)
  - Real-time game history
  - Interactive color picker
  - Status monitoring
  - Error notifications

## 📋 Requirements

```python
cryptography>=3.4.7
numpy>=1.21.0
tkinter (included with Python)
```

## 🚀 Quick Start

### Installation
```bash
git clone [https://github.com/KiwiTrue/mastermind-secure.git](https://github.com/KiwiTrue/Crypto-project.git)
cd mastermind-secure
pip install numpy cryptography
```

### Running the Game

#### Server
```bash
python main.py
```

#### Client
```bash
python player.py <player_name>
```

## 📖 Game Rules

1. 🎲 Codemaster generates a random 5-color sequence
2. 🎮 Players take turns guessing the sequence
3. ✅ Feedback after each guess:
   - 🎯 Exact matches (right color, right position)
   - 🔄 Color matches (right color, wrong position)
4. 🏆 First correct guess wins!

### Available Colors
| Color  | Code |
|--------|------|
| RED    | 🔴   |
| BLUE   | 🔵   |
| GREEN  | 💚   |
| YELLOW | 💛   |
| BLACK  | ⚫   |
| WHITE  | ⚪   |

## 📁 Project Structure

```
mastermind-secure/
├── 🎮 main.py           # Server & initialization
├── 🎲 codemaster.py     # Game logic
├── 👤 player.py         # CLI client
├── 🔐 ciphers.py        # Encryption
├── 📝 session.py        # Session management
├── 📊 logger.py         # Security logging
└── 🚀 launcher.py       # Quick start utility
```

## 🔒 Security Architecture

<details>
<summary>Authentication</summary>

- Public/private key pairs
- Secure session channels
</details>

<details>
<summary>Encryption</summary>

- Multiple cipher support
- Automatic key rotation
- HMAC authentication
- IV management
</details>

<details>
<summary>Session Management</summary>

- Unique session IDs
- Key rotation
- State tracking
</details>


## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

<div align="center">
Made with ❤️ by Your Team
</div>
```

Key improvements:
1. Added emojis for visual appeal
2. Created collapsible sections using `<details>`
3. Added badges at the top
4. Better section organization with horizontal rules
5. Added tables for better data presentation
6. Improved code block formatting
7. Added centered elements
8. Better visual hierarchy with headers
9. Added icons to project structure
10. Added centered footer

