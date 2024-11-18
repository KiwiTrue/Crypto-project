import tkinter as tk
from tkinter import ttk
from typing import List, Callable

class GameWindow(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Game history
        self.history = tk.Text(self, height=20, width=50)
        self.history.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status = ttk.Label(self, text="Waiting for connection...")
        self.status.pack(fill=tk.X, pady=(5,0))
        
    def add_message(self, message: str):
        self.history.insert(tk.END, f"{message}\n")
        self.history.see(tk.END)
        
    def add_status(self, status: str):
        self.status["text"] = status

class ColorPicker(ttk.Frame):
    def __init__(self, master, colors: List[str]):
        super().__init__(master)
        self.pack(fill=tk.X, padx=10, pady=5)
        
        # Color buttons
        self.colors = colors
        self.selected_colors = []
        
        for color in colors:
            btn = ttk.Button(
                self, 
                text=color,
                command=lambda c=color: self._select_color(c)
            )
            btn.pack(side=tk.LEFT, padx=2)
            
        # Submit button
        self.submit_btn = ttk.Button(
            self,
            text="Submit Guess",
            command=self._submit_guess
        )
        self.submit_btn.pack(side=tk.RIGHT, padx=2)
        
        # Clear button
        self.clear_btn = ttk.Button(
            self,
            text="Clear",
            command=self._clear_selection
        )
        self.clear_btn.pack(side=tk.RIGHT, padx=2)
        
        # Selection display
        self.selection_var = tk.StringVar()
        self.selection_label = ttk.Label(self, textvariable=self.selection_var)
        self.selection_label.pack(side=tk.LEFT, padx=10)
        
        self.on_submit: Callable[[str], None] = lambda x: None
        
    def _select_color(self, color: str):
        if len(self.selected_colors) < 5:
            self.selected_colors.append(color)
            self._update_display()
            
    def _clear_selection(self):
        self.selected_colors.clear()
        self._update_display()
        
    def _update_display(self):
        self.selection_var.set(", ".join(self.selected_colors))
        
    def _submit_guess(self):
        if len(self.selected_colors) == 5:
            guess = ",".join(self.selected_colors)
            self.on_submit(guess)
            self._clear_selection()
