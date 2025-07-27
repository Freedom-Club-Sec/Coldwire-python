from tkinter import messagebox
from tkinter import PhotoImage
from ui.connect_window import ServerConnectWindow
from ui.chat_window import ChatWindow 
from ui.password_prompt import PasswordPrompt
from ui.add_contact_prompt import AddContactPrompt
from ui.smp_setup_window import SMPSetupWindow
from ui.smp_question_window import SMPQuestionWindow
from ui.contact_nickname_prompt import ContactNicknamePrompt
from logic.authentication import authenticate_account
from logic.storage import check_account_file, save_account_data, load_account_data
from logic.background_worker import background_worker
from logic.utils import thread_failsafe_wrapper
import tkinter as tk
import sys
import os
import threading
import queue
import logging
import json
import atexit

logger = logging.getLogger(__name__)


class ContactListWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.withdraw() 
        self.contact_frame = None
        self.label = None

        self.user_data_lock = threading.Lock()
        self.ui_queue = queue.Queue()
        self.after(100, self.poll_ui_queue)

        # If no account information saved, we prompt user to connect to a server
        if not check_account_file():
            self.connect_popup = ServerConnectWindow(self)
        else:
            # This variable is so we don't have to call the callback inside the try block
            call_the_callback = False
            try:
                # first we try loading user data to see if its not encrypted
                # this is a dry run, we don't actually populate the user data here
                load_account_data(None)
                call_the_callback = True
            except:
                # otherwise we prompt for unlock password
                PasswordPrompt(self, self.ready_to_authenticate_callback)

            if call_the_callback:
                self.ready_to_authenticate_callback(None)

    def ready_to_authenticate_callback(self, password):
        self.user_data = load_account_data(password)
        try:
            self.user_data = authenticate_account(self.user_data)
        except ValueError as e:
            messagebox.showerror("Error", e)
            sys.exit(1)


        self.messages_store_tmp = {}
        self.chat_windows_store_tmp = {}

        self.show_contacts()
    def init_hooks_and_background_worker(self):
        self.worker_stop_flag = threading.Event()

        self.protocol("WM_DELETE_WINDOW", self.on_exit)
        atexit.register(self.on_exit)


        self.background_worker_thread = threading.Thread(target=thread_failsafe_wrapper, args=(background_worker, self.worker_stop_flag, self.ui_queue, self.user_data, self.user_data_lock, self.ui_queue, self.worker_stop_flag))

        self.background_worker_thread.start()

    def on_exit(self):
        self.worker_stop_flag.set()

        # Incase the GUI was already destroyed 
        try:
            self.destroy()
        except Exception:
            pass
        
        # We let the background_worker thread do the cleanup for its self, we already set the stop flag so it should know its time to exit
        self.background_worker_thread.join()

    def poll_ui_queue(self):
        try:
            while True:
                msg = self.ui_queue.get_nowait()
                logger.debug("Received a new message in UI queue: %s", json.dumps(msg, indent=2))
                
                if msg["type"] == "new_contact":
                    self.new_contact(msg["contact_id"])

                elif msg["type"] == "new_message":
                    if msg["contact_id"] in self.chat_windows_store_tmp:
                        self.chat_windows_store_tmp[msg["contact_id"]].lift()
                        self.chat_windows_store_tmp[msg["contact_id"]].focus_force()
                    else:
                        logger.debug("Opening chat window for contact (%s) because a new message arrived", msg["contact_id"])
                        self.chat_windows_store_tmp[msg["contact_id"]] = ChatWindow(self, msg["contact_id"], self.ui_queue)

                    with self.user_data_lock:
                        contact_nickname = self.user_data["contacts"][msg["contact_id"]]["nickname"]
                   

                    if not contact_nickname:
                        contact_nickname = "Contact"

                    self.chat_windows_store_tmp[msg["contact_id"]].append_message(contact_nickname + ": " + msg["message"], contact_nickname=contact_nickname)
            
                elif msg["type"] == "chat_closed":
                    del self.chat_windows_store_tmp[msg["contact_id"]]
                    logger.debug("Chat window for contact (%s) has been closed and therefore deleted", msg["contact_id"])

                elif msg["type"] == "smp_question":
                    SMPQuestionWindow(self, msg["contact_id"], msg["question"])
                
                elif msg["type"] == "showinfo":
                    messagebox.showinfo(msg["title"], msg["message"])

                elif msg["type"] == "showwarning":
                    messagebox.showwarning(msg["title"], msg["message"])

                elif msg["type"] == "showerror":
                    messagebox.showerror(msg["title"], msg["message"])
                
                elif msg["type"] == "exit":
                    logger.warning("Received exit signal, probably a thread crashed")
                    self.quit() 
                

        except queue.Empty:
            pass
        
        self.after(100, self.poll_ui_queue)


    def show_contacts(self):
        with self.user_data_lock:
            self.title(f"Coldwire – Connected to {self.user_data['server_url']}")
            username = self.user_data['user_id']

        self.geometry("300x500")
        self.configure(bg="black")
        self.deiconify()

        user_frame = tk.Frame(self, bg="black")
        user_frame.pack(pady=(10, 0))

        tk.Label(
            user_frame,
            text="Your ID: ",
            fg="white",
            bg="black",
            font=("Helvetica", 12)
        ).pack(side="left")

        username_label = tk.Label(
            user_frame,
            text=username,
            fg="white",
            bg="black",
            font=("Helvetica", 12),
            cursor="hand2"
        )
        username_label.pack(side="left")
        username_label.bind("<Button-1>", lambda e: self.copy_to_clipboard(username, "Your User ID has been copied to clipboard."))

        header_frame = tk.Frame(self, bg="black")
        header_frame.pack(pady=10)

        self.label = tk.Label(
            header_frame,
            text="Contacts",
            fg="white",
            bg="black",
            font=("Helvetica", 14, "bold")
        )
        self.label.pack(side="left")

        plus_icon = PhotoImage(file=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets", "icons", "plus_sign.png")))
        add_button = tk.Button(
            header_frame,
            image=plus_icon,
            command=self.open_add_contact_prompt,
            bg="black",
            relief="flat",
            bd=0,
            highlightthickness=0,
            activebackground="black"
        )
        add_button.image = plus_icon # Prevents garbage collection
        add_button.pack(side="left", padx=(5, 0))



        canvas = tk.Canvas(self, bg="black", highlightthickness=0)
        scrollbar = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.contact_frame = tk.Frame(canvas, bg="black")

        self.contact_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        contact_window = canvas.create_window((0, 0), window=self.contact_frame, anchor="nw")

        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")) # Windows / Linux mouse scrolling support
        canvas.bind_all("<Button-4>", lambda e: canvas.yview_scroll(-1, "units")) # MacOS
        canvas.bind_all("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))  # MacOS again

        canvas_frame = canvas.create_window((0, 0), window=self.contact_frame, anchor="nw")

        canvas.bind("<Configure>", lambda e: canvas.itemconfig(canvas_frame, width=e.width))


        # Draw our saved contacts
        self.draw_contact_list()

        # We initialize the background worker thread and other hooks here to prevent race conditions
        self.init_hooks_and_background_worker()

    def on_mousewheel(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")


    def new_contact(self, contact_id):
        with self.user_data_lock:
            contact_name = contact_id if not self.user_data["contacts"][contact_id]["nickname"] else self.user_data["contacts"][contact_id]["nickname"]
            contact_is_verified = self.user_data["contacts"][contact_id]["lt_sign_key_smp"]["verified"]

        button = tk.Button(
            self.contact_frame,
            text=contact_name,
            bg="gray15",
            fg="white",
            relief="flat",
            anchor="w",
            command=lambda: self.open_chat(contact_id)
        )
        button.pack(fill="x", padx=15, pady=5)

        context_menu = tk.Menu(self, tearoff=0)
        context_menu.add_command(
                label="Copy Contact ID", 
                command=lambda: self.copy_to_clipboard(contact_id, "Contact ID has been copied to the clipboard")
            )
        context_menu.add_separator()

        # If no nickname is set
        if (contact_name == contact_id):
            # We only allow setting nicknames after SMP verification succeeds 
            if contact_is_verified:
                context_menu.add_command(
                    label="Set nickname", 
                    command=lambda: self.change_contact_nickname(contact_id)
                )
        else:
            context_menu.add_command(
                    label="Change nickname", 
                    command=lambda: self.change_contact_nickname(contact_id)
                )

            context_menu.add_separator()
            
            context_menu.add_command(
                    label="Remove nickname", 
                    command=lambda: self.remove_contact_nickname(contact_id)
                )

        button.bind("<Button-3>", lambda event: context_menu.tk_popup(event.x_root, event.y_root))  # Windows / Linux
        button.bind("<Button-2>", lambda event: context_menu.tk_popup(event.x_root, event.y_root))  # MacOS

    def change_contact_nickname(self, contact_id):
        ContactNicknamePrompt(self, contact_id)

    def remove_contact_nickname(self, contact_id):
        with self.user_data_lock:
            self.user_data["contacts"][contact_id]["nickname"] = None

        logger.info("Removed nickname for contact (%s)", contact_id)
        save_account_data(self.user_data, self.user_data_lock)
        self.draw_contact_list()

    def draw_contact_list(self):
        logger.debug("Redrawing the contact list")
        for widget in self.contact_frame.winfo_children():
            widget.destroy()

        with self.user_data_lock:
            contact_ids = list(self.user_data["contacts"].keys())

        for contact_id in self.user_data["contacts"]:
            self.new_contact(contact_id)

        logger.debug("Redrew the contact list")
    def copy_to_clipboard(self, text, success_message):
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copied", success_message)

    def open_chat(self, contact_id):
        with self.user_data_lock:
            contact_smp_info = self.user_data["contacts"][contact_id]["lt_sign_key_smp"]
            contact_verified = contact_smp_info["verified"]
            contact_pending_verification = contact_smp_info["pending_verification"]

        if contact_verified:
            if contact_id in self.chat_windows_store_tmp:
                self.chat_windows_store_tmp[contact_id].lift()
                self.chat_windows_store_tmp[contact_id].focus_force()
            else:
                logger.info("Opening chat window for contact (%s)", contact_id)

                self.chat_windows_store_tmp[contact_id] = ChatWindow(self, contact_id, self.ui_queue)

            return

        elif contact_pending_verification:
            messagebox.showinfo("SMP Verification", "Still pending verification process, we will notify you when contact is verified")
            return
       
        SMPSetupWindow(self, contact_id)

    def open_add_contact_prompt(self):
        AddContactPrompt(self)


