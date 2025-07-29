import tkinter as tk

def enhanced_entry(entry, placeholder=None, show=""):
    entry.bind("<Control-a>", select_all)
    
    if placeholder and not entry.get():
        add_placeholder(entry, placeholder, show=show)
    return entry

def add_placeholder(entry, placeholder, color="gray50", show=""):
    normal_fg = entry.cget("fg")  # Remember original color
    placeholder_state = {"active": True}  # Track if placeholder is active

    def set_placeholder():
        entry.delete(0, "end")
        entry.insert(0, placeholder)
        entry.config(fg=color, show="")
        placeholder_state["active"] = True

    def clear_placeholder():
        if placeholder_state["active"]:
            entry.delete(0, "end")
        entry.config(fg=normal_fg, show=show)
        placeholder_state["active"] = False

    def on_focus_in(event):
        if placeholder_state["active"]:
            clear_placeholder()

    def on_focus_out(event):
        if not entry.get():
            set_placeholder()

    def on_key(event):
        if placeholder_state["active"]:
            clear_placeholder()

    original_get = entry.get
    def safe_get():
        if placeholder_state["active"]:
            return ""
        return original_get()

    entry.get = safe_get

    set_placeholder()

    entry.bind("<FocusIn>", on_focus_in)
    entry.bind("<FocusOut>", on_focus_out)
    entry.bind("<Key>", on_key)

def select_all(event=None):
    event.widget.select_range(0, 'end')
    event.widget.icursor('end')
    return "break"

def fake_readonly(event):
    # Allow Ctrl+C (copy) and Ctrl+A (select all)
    # tk. doesn't support customizing Read-only entries, this hacks around it while still allowing copying
    if (event.state & 0x4 and event.keysym.lower() in ("c", "a")):
        return
    return "break"  # Block everything else


class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        if self.tip_window or not self.text:
            return
        x, y, _, _ = self.widget.bbox("insert") or (0, 0, 0, 0)
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20

        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True) 
        tw.wm_geometry(f"+{x}+{y}")

        label = tk.Label(
            tw,
            text=self.text,
            justify="left",
            background="black",
            foreground="white",
            relief="solid",
            borderwidth=1,
            font=("Helvetica", 9)
        )
        label.pack(ipadx=5, ipady=2)

    def hide_tip(self, event=None):
        tw = self.tip_window
        self.tip_window = None
        if tw:
            tw.destroy()

