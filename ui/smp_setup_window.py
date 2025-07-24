import tkinter as tk
from tkinter import messagebox
from ui.utils import *
from logic.smp import initiate_smp

class SMPSetupWindow(tk.Toplevel):
    def __init__(self, master, contact_id):
        super().__init__(master)
        self.contact_id = contact_id

        self.title("Set Verification Question")
        self.geometry("400x250")
        self.configure(bg="black")

        # Instructions label
        tk.Label(
            self,
            text="Pick a question that only you and your contact would know.\nAvoid anything guessable. No birthdays. No public facts.",
            fg="white",
            bg="black",
            font=("Helvetica", 10),
            wraplength=380,
            justify="left"
        ).pack(pady=(10, 10))

        # Question input
        tk.Label(self, text="Question:", fg="white", bg="black", anchor="w").pack(fill="x", padx=20)
        self.question_entry = tk.Entry(self, width=50)
        self.question_entry.pack(padx=20, pady=(0, 10))
        self.question_entry.focus()

        # Answer input
        tk.Label(self, text="Answer:", fg="white", bg="black", anchor="w").pack(fill="x", padx=20)
        self.answer_entry = tk.Entry(self, width=50)
        self.answer_entry.pack(padx=20, pady=(0, 20))

        # enhanced_entry(self.question_entry, placeholder="I.e. Where did we meet last Thursday ?")
        # enhanced_entry(self.answer_entry, placeholder="I.e. Central Park")

        # Send button
        tk.Button(
            self,
            text="Send Verification Request",
            command=self.submit,
            bg="gray20",
            fg="white",
            relief="flat"
        ).pack(pady=(0, 10))

        self.bind("<Return>", lambda e: self.submit())
        self.transient(master)
        self.grab_set()

    def submit(self):
        question = self.question_entry.get().strip()
        answer = self.answer_entry.get().strip().lower()
        if not question or not answer:
            messagebox.showerror("Error", "Both fields are required.")
            return

        if len(question) > 512:
            messagebox.showerror("Error", "Question should be under 512 characters long")

        initiate_smp(self.master.user_data, self.master.user_data_lock, self.contact_id, question, answer)

        self.destroy()
