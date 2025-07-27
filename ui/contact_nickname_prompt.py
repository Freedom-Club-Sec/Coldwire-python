from tkinter import messagebox
from ui.utils import *
from logic.contacts import generate_random_nickname
from logic.storage import save_account_data
import tkinter as tk
import logging

logger = logging.getLogger(__name__)

class ContactNicknamePrompt(tk.Toplevel):
    def __init__(self, master, contact_id):
        super().__init__(master)
        self.title("Set Nickname")
        self.geometry("460x300")
        self.configure(bg="black")
        self.resizable(False, False)

        self.contact_id = contact_id
        self.random_nickname = None

        # Top warning text (We use text instead of label to color key warning parts)
        warning_text = tk.Text(
                self, 
                bg="black", 
                fg="white", 
                font=("Helvetica", 11), 
                wrap="word", 
                height=9, 
                width=50, 
                borderwidth=0, 
                highlightthickness=0,
                relief="flat"
            )
        warning_text.insert("1.0", "Choose an anonymous nickname.\n")
        warning_text.insert("end", "Do NOT ", "warning_italic") 
        warning_text.insert("end", "use real names or anything identifying.\n")
        warning_text.insert("end", "Good ", "good_bold")
        warning_text.insert("end", "examples: Contact 1, Friend A, C1, etc.\n")
        warning_text.insert("end", "Bad   ", "warning_bold") 
        warning_text.insert("end", "examples: George, CIA contact, Z Dealer, etc.\n\n")
        warning_text.insert("end", "WARNING: ", "warning_bold")
        warning_text.insert("end", "If your device hard disk is ever compromised, custom nicknames can link handles to people.\n") 
        warning_text.insert("end", "Please proceed with EXTREME caution.", "warning_italic")

        warning_text.tag_config("italic", font=("Helvetica", 10, "italic"))
        warning_text.tag_config("warning_bold", font=("Helvetica", 10, "bold"), foreground="red")
        warning_text.tag_config("warning_italic", font=("Helvetica", 10, "italic"), foreground="red")

        warning_text.tag_config("good_bold", font=("Helvetica", 10, "bold"), foreground="green")

        warning_text.configure(state="disabled")
        warning_text.pack(pady=(10, 10))


        # Entry + generator button container
        entry_frame = tk.Frame(self, bg="black")
        entry_frame.pack(pady=5)

        self.entry = tk.Entry(entry_frame, font=("Helvetica", 12), width=20)
        self.entry.pack(side="left", padx=(0, 5))
        self.entry.focus()

        # Random nickname generator button
        tk.Button(
            entry_frame,
            text="Randomize",
            command=self.generate_nickname,
            bg="gray25",
            fg="white",
            font=("Helvetica", 10, "bold"),
            width=10
        ).pack(side="left")

        # Save button
        tk.Button(
            self,
            text="Save nickname",
            command=self.submit_nickname,
            bg="gray20",
            fg="white",
            font=("Helvetica", 10, "bold"),
            width=15
        ).pack(pady=15)

        # Enter key = save
        self.entry.bind("<Return>", lambda e: self.submit_nickname())

    def generate_nickname(self):
        nickname = generate_random_nickname(self.master.user_data, self.master.user_data_lock, self.contact_id)
        self.random_nickname = nickname

        self.entry.delete(0, tk.END)
        self.entry.insert(0, nickname)

    def submit_nickname(self):
        nickname = self.entry.get().strip()
        
        if not nickname:
            messagebox.showerror("Error", "Field cannot be empty!")
            return

        if len(nickname) > 32:
            messagebox.showerror("Error", "Nickname must be less than 32 characters long!")
            return1

        if nickname != self.random_nickname:
            if not messagebox.askyesno(
                "Warning",
                "You did not use the Randomize button.\n\n"
                "Custom nicknames can link your contacts to real-world identities.\n"
                "This risks their privacy if your device is ever compromised.\n\n"
                "Are you sure you want to proceed?"
            ):
                return

            if not messagebox.askyesno(
                "Final Warning",
                "Custom nicknames can permanently compromise both your privacy and your contact’s.\n"
                "If your device is ever seized or leaked, this link may expose real identities.\n\n"
                "Are you ABSOLUTELY sure you want to proceed?"
            ):
                return

        with self.master.user_data_lock:
            self.master.user_data["contacts"][self.contact_id]["nickname"] = nickname

        save_account_data(self.master.user_data, self.master.user_data_lock)
        logger.info("Updated contact (%s) nickname to: %s", self.contact_id, nickname)

        self.master.draw_contact_list()
        self.destroy()
