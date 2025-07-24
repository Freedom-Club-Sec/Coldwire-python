def enhanced_entry(entry, placeholder=None, show=""):
    entry.bind("<Control-a>", select_all)
    if placeholder:
        add_placeholder(entry, placeholder, show=show)
    
    return entry


def add_placeholder(entry, placeholder, color="gray50", show=""):
    def on_focus_in(event):
        if entry.get() == placeholder:
            entry.delete(0, "end")
            entry.config(fg="white", show="")
        else:
            entry.config(show=show)

    def on_focus_out(event):
        if entry.get() == "":
            entry.insert(0, placeholder)
            entry.config(fg=color, show="")
        elif entry.get() != placeholder:
            entry.config(show=show)


    def on_key(event):
        entry.config(show=show)

    entry.insert(0, placeholder)
    entry.config(fg=color)
    entry.bind("<FocusIn>", on_focus_in)
    entry.bind("<FocusOut>", on_focus_out)
    entry.bind("<Key>", on_key)

def select_all(event=None):
    event.widget.select_range(0, 'end')
    event.widget.icursor('end')
    return "break"


