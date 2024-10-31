# Mastermind Game Project


## Table of Contents
- [Project Overview](#project-overview)
- [Team Requirements](#team-requirements)
- [Project Phases and Tasks](#project-phases-and-tasks)
  - [Phase 1: Historical Symmetric Key Encryption Algorithms](#phase-1-historical-symmetric-key-encryption-algorithms)
  - [Phase 2: Modern Symmetric Key Ciphers](#phase-2-modern-symmetric-key-ciphers)
  - [Phase 3: Game Logic and Rules](#phase-3-game-logic-and-rules)
  - [Phase 4: Network Communication](#phase-4-network-communication)
  - [Phase 5: Certification Authority (CA) for Key Distribution](#phase-5-certification-authority-ca-for-key-distribution)
  - [Phase 6 (Bonus): Graphical User Interface (GUI)](#phase-6-bonus-graphical-user-interface-gui)
- [Files in the Project](#files-in-the-project)
- [Starting the Project](#starting-the-project)
- [Deliverables](#deliverables)
- [Submission Deadlines](#submission-deadlines)

---

## Project Overview

This project involves designing and implementing a secure, networked version of the classic Mastermind game. The game allows two players to connect over a network and take turns guessing a hidden sequence of colors chosen by the Codemaster. Secure communication is essential, with encryption applied to all messages exchanged.

## Team Requirements
- Team of 4-5 students

## Project Phases and Tasks

### Phase 1: Historical Symmetric Key Encryption Algorithms
- Implement encryption and decryption functions for each of the following ciphers:
  - Caesar (shift) cipher
  - Monoalphabetic cipher
  - Homophonic cipher
  - Playfair cipher
  - Vigenere cipher
  - Autokey cipher
  - Rail fence cipher
  - Columnar transposition cipher
  - Affine cipher
  - Hill cipher

### Phase 2: Modern Symmetric Key Ciphers
- **Task 2.1**: Select and justify a suitable cryptography library for modern symmetric ciphers (e.g., `pycryptodome` for Python).
- **Task 2.2**: Implement encryption and decryption using the chosen library with the following algorithms:
  - DES
  - 3DES
  - AES
  - Blowfish
  - RC5

### Phase 3: Game Logic and Rules
- **Objective**: Players attempt to guess the Codemaster's hidden color sequence.
- **Codemaster's Role**: Selects a sequence of colors and provides feedback after each player’s guess.
- **Player's Role**: Guess the sequence based on feedback to narrow down to the correct answer.
- **Feedback Types**:
  - **Exact Match**: Correct color and position.
  - **Color Match**: Correct color, wrong position.
- **Winning Condition**: The first player to guess the exact sequence wins.

#### Game Setup
- Colors: Red, Blue, Green, Yellow, White, Black
- Sequence Length: Typically 5 colors

### Phase 4: Network Communication
- **Model**: Client-server (Codemaster as server, players as clients).
- **Socket Communication**: Use TCP sockets to send guesses and receive feedback.
- **Encryption**: Messages are encrypted using ciphers from Phases 1 and 2, with a “No-encryption” option for unencrypted communication.

### Phase 5: Certification Authority (CA) for Key Distribution
- **Key Setup**: Generate public/private keys and obtain a certificate from the CA.
- **Protocol Design**:
  - Propose and implement a protocol to select and distribute symmetric keys securely.
  - Define methods to generate and distribute symmetric keys.

### Phase 6 (Bonus): Graphical User Interface (GUI)
- Implement an optional GUI for player interaction using a framework like `tkinter`.

## Files in the Project

- **Codemaster.py**: Manages server-side logic and Codemaster actions.
- **Player.py**: Handles client-side logic and player actions.
- **CertificationAuthority.py**: Manages key generation and certificate distribution.
- **CryptoFunctions.py**: Contains encryption and decryption functions.
- **GameLogic.py**: Core game functions, including sequence generation and feedback evaluation.
- **GUI.py**: Graphical interface for players (optional).
- **Main.py**: Entry point, initializes and coordinates all components.

## Starting the Project

1. **Install Dependencies**:
   ```bash
   pip install pycryptodome
