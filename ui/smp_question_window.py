import tkinter as tk
from tkinter import messagebox
# from ui.utils import *
from logic.smp import smp_step_2_answer_provided

class SMPQuestionWindow(tk.Toplevel):
    def __init__(self, master, contact_id, question):
        super().__init__(master)
        self.contact_id = contact_id

        self.title("Answer Verification Question")
        self.geometry("400x250")
        self.configure(bg="black")

        # Question label
        # :512 to ensure no weird visual effects or even bufferoverflows can be exploited in the underlying tkinter library.
        tk.Label(
            self,
            text="Question: " + question[:512],
            fg="white",
            bg="black",
            font=("Helvetica", 10),
            wraplength=380,
            justify="left"
        ).pack(pady=(10, 10))

        # Answer input
        tk.Label(self, text="Answer:", fg="white", bg="black", anchor="w").pack(fill="x", padx=20)
        self.answer_entry = tk.Entry(self, width=50)
        self.answer_entry.pack(padx=20, pady=(0, 10))

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
        answer = self.answer_entry.get().strip().lower()
        if not answer:
            messagebox.showerror("Error", "You need to provide an answer.")
            return

        smp_step_2_answer_provided(self.master.user_data, self.master.user_data_lock, self.contact_id, answer, self.master.ui_queue)

        self.destroy()
