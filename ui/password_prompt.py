import tkinter as tk
from tkinter import messagebox
from logic.storage import load_account_data
from ui.utils import *

class PasswordPrompt(tk.Toplevel):
    def __init__(self, master, on_submit):
        super().__init__(master)
        self.title("Unlock Account")
        self.configure(bg="black")
        self.resizable(False, False)
        self.on_submit = on_submit

        self.label = tk.Label(
            self,
            text="Enter your password to decrypt locally saved account information.",
            bg="black",
            fg="white",
            wraplength=300,
            justify="left"
        )
        self.label.pack(padx=20, pady=(20, 10))

        self.password_var = tk.StringVar()
        self.entry = tk.Entry(
            self,
            textvariable=self.password_var,
            show="*",
            bg="gray15",
            fg="white",
            insertbackground="white",
            width=30
        )
        self.entry.pack(pady=5)
        self.entry.focus()
        self.entry.bind("<Return>", self.submit)

        self.toggle_var = tk.IntVar()
        self.toggle = tk.Checkbutton(
            self,
            text="Show password",
            variable=self.toggle_var,
            command=self.toggle_visibility,
            bg="black",
            fg="white",
            activebackground="black",
            activeforeground="white",
            selectcolor="black"
        )
        self.toggle.pack(pady=(0, 5))

        self.status_label = tk.Label(
            self,
            text="",
            bg="black",
            fg="red",
            wraplength=280
        )
        self.status_label.pack(pady=(0, 10))

        self.submit_btn = tk.Button(
            self,
            text="Unlock",
            command=self.submit,
            bg="gray25",
            fg="white"
        )
        self.submit_btn.pack(pady=(0, 20))

        enhanced_entry(self.entry)

        self.grab_set()

    def toggle_visibility(self):
        self.entry.config(show="" if self.toggle_var.get() else "*")

    def set_status(self, message: str):
        self.status_label.config(text=message)

    def submit(self, event=None):
        password = self.password_var.get()
        if not password:
            self.set_status("You need to enter a password")
            return

        try:
            load_account_data(password)
        except:
            self.set_status("Wrong password")
            return

        self.destroy()
        self.on_submit(password)

