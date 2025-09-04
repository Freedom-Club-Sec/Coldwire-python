from tkinter import messagebox
from logic.message import send_message_processor
from core.constants import (
       OTP_MAX_MESSAGE_LEN 
)
import tkinter as tk

class ChatWindow(tk.Toplevel):
    def __init__(self, master, contact_id, ui_queue):
        super().__init__(master)
        self.title(f"Chat – {contact_id}")
        self.geometry("700x500")
        self.configure(bg="black")

        self.chat_display = tk.Text(self, state="disabled", bg="black", fg="white", wrap="word")
        self.chat_display.pack(fill="both", expand=True, padx=10, pady=10)
        self.chat_display.tag_configure("you", foreground="#4EE44E")
        self.chat_display.tag_configure("contact", foreground="#F0382B")
        self.chat_display.tag_configure("coldwire", foreground="#2926D4")

        self.entry = tk.Text(self, height=2, bg="gray15", fg="white", insertbackground="white", wrap="word")
        self.entry.pack(fill="x", padx=10, pady=(0, 10))
        self.entry.focus()

        self.entry.bind("<Control-a>", self.select_all)
        self.entry.bind("<Return>", self.on_send)
        self.entry.bind("<Shift-Return>", self.newline)

        self.contact_id = contact_id
        self.ui_queue = ui_queue

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        
        if self.contact_id in self.master.messages_store_tmp:
            for msg in self.master.messages_store_tmp[self.contact_id]:
                self.append_message(msg, save_msg = False)
        else:
            self.master.messages_store_tmp[self.contact_id] = [] 

            self.append_message(f"* Chat initialized with {contact_id}")

    def on_close(self):
        self.ui_queue.put({
            "type": "chat_closed",
            "contact_id": self.contact_id
        })
        self.destroy()

    def on_send(self, event=None):
        message = self.entry.get("1.0", "end-1c").strip()
        if not message:
            return "break"

        if len(message) > OTP_MAX_MESSAGE_LEN:
            messagebox.showerror("Error", f"Your message length ({len(message)}) is too large! Messages must be under {OTP_MAX_MESSAGE_LEN}")
            return "break"

        self.entry.delete("1.0", "end")

        success = send_message_processor(self.master.user_data, self.master.user_data_lock, self.contact_id, message, self.master.ui_queue)
        if not success:
            self.entry.insert("1.0", message)
            return "break"


        self.append_message(f"You: {message}")
        return "break"

    def append_message(self, message: str, save_msg: bool = True, contact_nickname: str = "Contact"):
        self.chat_display.config(state="normal")
        if message.startswith("You:"):
            self.chat_display.insert("end", "You:", "you")
            self.chat_display.insert("end", message[4:] + "\n")
        
        elif message.startswith("*"):
            self.chat_display.insert("end", "*", "coldwire")
            self.chat_display.insert("end", message[1:] + "\n")
        
        else:
            self.chat_display.insert("end", contact_nickname + ":", "contact")
            self.chat_display.insert("end", message[len(contact_nickname): OTP_MAX_MESSAGE_LEN + len(contact_nickname)] + "\n")



        self.chat_display.config(state="disabled")
        self.chat_display.see("end")

        if save_msg:
            self.master.messages_store_tmp[self.contact_id].append(message)

    def select_all(self, event=None):
        self.entry.tag_add("sel", "1.0", "end-1c")
        return "break"

    def newline(self, event=None):
        self.entry.insert(tk.INSERT, "\n")
        return "break"



