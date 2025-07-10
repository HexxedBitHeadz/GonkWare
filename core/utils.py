import random, string

def rand_var(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def copy_msf_command(app):
    cmd = getattr(app, "full_msf_cmd", "No command yet")
    import pyperclip
    pyperclip.copy(cmd)

    # Set temporary status messages
    app.top_status_label.config(text="Command", foreground="#fefe00")
    app.bottom_status_label.config(text="Copied!", foreground="#fefe00")

    def blink_status(step=0):
        if step < 6:
            color = "#fefe00" if step % 2 == 0 else "#2e2e2e"
            app.top_status_label.config(foreground=color)
            app.bottom_status_label.config(foreground=color)
            app.root.after(200, lambda: blink_status(step + 1))
        else:
            # Restore original messages and colors
            app.top_status_label.config(text="Shellcode", foreground="#00ff00")
            app.bottom_status_label.config(text="Generated", foreground="#00ff00")

    blink_status()

def update_msf_entry(app, text, fg="#000000", bg="#FEFE00", insert_bg="#000000"):
    app.msf_entry.configure(
        state="normal",
        foreground=fg,
        background=bg,
        insertbackground=insert_bg
    )
    app.msf_entry.delete("1.0", "end")
    app.msf_entry.insert("1.0", text)
    app.msf_entry.configure(state="disabled")
    app.msf_entry.tag_add("left", "1.0", "end")

