import tkinter as tk
import copy
import logging
from logic.storage import save_account_data
from tkinter import messagebox
from ui.utils import (
    ToolTip,
    fake_readonly,
    enhanced_entry
)

logger = logging.getLogger(__name__)

class SettingsWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Settings")
        self.configure(bg="black")
        self.geometry("450x300")
        self.resizable(False, False)

        with self.master.user_data_lock:
            self.user_data_copied = copy.deepcopy(self.master.user_data)

        tk.Label(
            self,
            text="Settings",
            fg="white",
            bg="black",
            font=("Helvetica", 14, "bold")
        ).pack(pady=10)

        self.ignore_new_contacts_var = tk.BooleanVar(value = self.user_data_copied["settings"]["ignore_new_contacts_smp"])
        ignore_new_contacts_checkbox = tk.Checkbutton(
            self,
            text="Ignore unknown new verification requests",
            variable=self.ignore_new_contacts_var,
            fg="white",
            bg="black",
            selectcolor="black",
            activebackground="black",
            activeforeground="white"
        )
        ignore_new_contacts_checkbox.pack(anchor="w", padx=20, pady=5)
        ToolTip(ignore_new_contacts_checkbox, "Ignores SMP verification requests from people not already saved in your contacts")



        server_frame = tk.Frame(self, bg="black")
        server_frame.pack(fill="x", padx=20, pady=5)

        tk.Label(server_frame, text="Server URL:", fg="white", bg="black").pack(side="left", padx=(0, 5))

        self.server_entry = tk.Entry(server_frame, bg="gray15", fg="white", insertbackground="white", highlightthickness=0)
        self.server_entry.insert(0, self.user_data_copied["server_url"])
        self.server_entry.bind("<Key>", fake_readonly)
        self.server_entry.pack(fill="x", padx=5, pady=5)

       
        proxy_frame = tk.Frame(self, bg="black")
        proxy_frame.pack(fill="x", padx=20, pady=5)

        tk.Label(proxy_frame, text="Proxy Type:", fg="white", bg="black").pack(side="left", padx=(0, 5))

        proxy_info = self.user_data_copied["settings"]["proxy_info"]
        proxy_type     = "None"
        proxy_address  = ""
        proxy_username = ""
        proxy_password = ""

        if proxy_info:
            proxy_type = proxy_info["type"]
            proxy_address = f"{proxy_info['host']}:{proxy_info['port']}"
            proxy_username = proxy_info["username"]
            proxy_password = proxy_info["password"]


        self.proxy_type_var = tk.StringVar(value = proxy_type)
        proxy_menu = tk.OptionMenu(proxy_frame, self.proxy_type_var, "None", "SOCKS5", "SOCKS4", "HTTP")
        proxy_menu.config(bg="gray15", fg="white", activebackground="gray25", activeforeground="white", highlightthickness=0)
        proxy_menu["menu"].config(bg="gray15", fg="white", activebackground="gray25", activeforeground="white")
        proxy_menu.pack(side="left", padx=(0, 5))

        self.proxy_address_entry = tk.Entry(proxy_frame, bg="gray15", fg="white", insertbackground="white", highlightthickness=0)
        self.proxy_address_entry.insert(0, proxy_address)
        self.proxy_address_entry.pack(side="left", fill="x", expand=True)

        proxy_cred_frame = tk.Frame(self, bg="black")
        proxy_cred_frame.pack(fill="x", padx=20, pady=(2, 10))

        self.proxy_username_entry = tk.Entry(proxy_cred_frame, bg="gray15", fg="white", insertbackground="white", highlightthickness=0)
        self.proxy_username_entry.insert(0, proxy_username)
        self.proxy_username_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))

        self.proxy_password_entry = tk.Entry(proxy_cred_frame,bg="gray15", fg="white", insertbackground="white", highlightthickness=0, show="*")
        self.proxy_password_entry.insert(0, proxy_password)
        self.proxy_password_entry.pack(side="left", fill="x", expand=True)

        enhanced_entry(self.proxy_address_entry, placeholder="Proxy server address")
        enhanced_entry(self.proxy_username_entry, placeholder="Proxy username (optional)")
        enhanced_entry(self.proxy_password_entry, placeholder="Proxy password (optional)", show="*")

        tk.Button(self, text="Save Settings", 
                  font=("Helvetica", 12), 
                  bg="gray20", fg="white", 
                  activebackground="gray30", 
                  activeforeground="white", 
                  command=self.save_settings
            ).pack(side="left", padx=(100, 0), pady=10)

        tk.Button(self, text="Cancel", 
                  font=("Helvetica", 12), 
                  bg="gray20", 
                  fg="white", 
                  activebackground="gray30", 
                  activeforeground="white", 
                  command=self.destroy
            ).pack(side="right", padx=(0, 100), pady=10)

        self.transient(master)
        self.grab_set()

    def save_settings(self):
        proxy_type = self.proxy_type_var.get()
        proxy_address = self.proxy_address_entry.get().strip()
       
        if proxy_type != "None":
            if proxy_type in ["SOCKS5", "SOCKS4"]:
                try:
                    import socks
                except ImportError:
                    logger.error("SOCKS proxy set and we could not find PySocks. WARNING before you install PySocks: PySocks is largely unmaintained. It's highly recommended you use proxychains instead")
                    messagebox.showerror("Error", "You need to install PySocks to enable SOCKS proxy support!")
                    return

            if not proxy_address or ':' not in proxy_address:
                messagebox.showerror("Error", "You did not enter a valid proxy address!")
                return

            proxy_username = self.proxy_username_entry.get().strip()
            proxy_password = self.proxy_password_entry.get().strip()

            host, port = proxy_address.split(':', 1)
            
            try:
                port = int(port)
            except ValueError:
                messagebox.showerror("Error", "Invalid proxy address port!")
                return

            with self.master.user_data_lock:
                self.master.user_data["settings"]["proxy_info"] = {
                        "type": proxy_type,
                        "host": host,
                        "port": port,
                        "username": proxy_username,
                        "password": proxy_password
                    }

        with self.master.user_data_lock:
            self.master.user_data["settings"]["ignore_new_contacts_smp"] = self.ignore_new_contacts_var.get()

        save_account_data(self.master.user_data, self.master.user_data_lock)
        messagebox.showinfo("Settings", "Settings saved!")
        self.destroy()
