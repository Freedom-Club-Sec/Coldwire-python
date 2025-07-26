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
            text="Pick a question that only you and your contact would know.\nCommunicate out-of-band if needed. Avoid anything guessable. No birthdays. No public facts.",
            fg="white",
            bg="black",
            font=("Helvetica", 10),
            wraplength=380,
            justify="left"
        ).pack(pady=(10, 10))

        tk.Label(self, text="Question:", fg="white", bg="black", anchor="w").pack(fill="x", padx=20)
        self.question_entry = tk.Entry(self, width=50)
        self.question_entry.pack(padx=20, pady=(0, 10))
        self.question_entry.focus()

        tk.Label(self, text="Answer:", fg="white", bg="black", anchor="w").pack(fill="x", padx=20)
        self.answer_entry = tk.Entry(self, width=50)
        self.answer_entry.pack(padx=20, pady=(0, 20))

        # TODO: Figure out why enhanced_entry bricks the question and answer entry
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

        if question.lower() == answer:
            messagebox.showerror("Error", "The question and answer must be different!")
            return

        
        if answer in question.lower():
            messagebox.showerror("Error", "Question must not contain the answer!")
            return


        if len(question) > 512:
            messagebox.showerror("Error", "Question must be under 512 characters long.")


        # This is just unacceptable, 4 characaters is the bare minimum.
        # Given our argon2id parameters, we have calculated the worst case scenario of an adversary with 
        # many 128-core CPU clusters, and 1000s of machines available, with custom-optimizied cracking-rigs
        # and we concluded that as of 2025, would still require a couple minutes - couple seconds short of 
        # a minute to crack the answer which might *just* be enough time if both users are online and the 
        # server is not malicious. If the server is malicious, it could delay the process, which means that 
        # powerful adversary would have cracked the answer to your question and possibly fed you spoofed keys
        # 
        # We don't actually enforce high-entropy answers because we know users will try to bypass the limit
        # by picking long-length but low-entropy answers, or worse, put / hint the answer in the question
        # Instead, we opted for an approach of allowing the user to choose low-entropy answers but give
        # them 2 warnings to ensure they understand the risks.
        # 

        if len(answer) <= 3:
            messagebox.showerror("Error", "Answer must be at least 4 characters long!")
            return

        if len(answer) <= 5:
            # Even though we enforce SMP, sometime a user might want to add someone whom our user don't have a out-of-band channel to communicate with
            # allowing the user to set a low-entropy answer gives user the opportunity to do so
            # But we still warn the user twice about the importance of the answer's entropy in context of SMP verification
            if messagebox.askyesno("Warning", "Answer is less than 6 characters long, this is unsafe and not recommended, do you want to proceed anyway ?"):
                if not messagebox.askyesno("Warning", "If the server is malicious, low-entropy answer potentially undermines encryption. To reduce risks only proceed if you are certain that the contact is online right now, are you absolutely sure?"):
                    return
            else:
                return

        initiate_smp(self.master.user_data, self.master.user_data_lock, self.contact_id, question, answer)

        self.destroy()
