# ui_helpers.py - UI utilities and styling

import random
import string

# === UTILITY FUNCTIONS ===

def rand_var(length=8):
    """Generate random variable name"""
    return ''.join(random.choices(string.ascii_letters, k=length))

def copy_msf_command(app):
    """Copy MSF command to clipboard with visual feedback"""
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
            app.top_status_label.config(text="Status", foreground="#ec1c3a")
            app.bottom_status_label.config(text="Ready", foreground="#91ddd3")

    blink_status()

def update_msf_entry(app, text):
    """Update MSF command entry text"""
    if hasattr(app, 'msf_entry'):
        app.msf_entry.insert("1.0", text)
        app.msf_entry.configure(state="disabled")

# === UI STYLING ===

def configure_styles(style):
    """Configure styles for ttk widgets"""
    base_label_config = {
        "font": ("Consolas", 15, "bold"),
        "background": "#000000"
    }

    # Labels
    style.configure("BaseLabel.TLabel", **base_label_config)
    style.configure("SectionLabel.TLabel", **base_label_config, foreground="#91ddd3")
    style.configure("MSFLabel.TLabel", **base_label_config, foreground="#fefe00")
    style.configure("SleepLabel.TLabel", **base_label_config, foreground="#3B5BB7")
    style.configure("StatusLabel.TLabel", **base_label_config, foreground="#EC1C3A")
    style.configure("BottomStatusLabel.TLabel", font=("Consolas", 13, "italic"), foreground="#91ddd3", background="#000000")

    # Checkbuttons
    style.configure("Neon.TCheckbutton",
        font=("Consolas", 15, "bold"),
        focuscolor="none",
        background="#000000",
        foreground="#91ddd3")

    # Comboboxes  
    style.configure("Neon.TCombobox",
        font=("Consolas", 12, "bold"),
        fieldbackground="#2e2e2e",
        background="#000000",
        foreground="#91ddd3",
        borderwidth=1,
        relief="solid",
        bordercolor="#91ddd3")

    # Red/Black Comboboxes for dropdowns
    style.configure("RedCombo.TCombobox",
        font=("Consolas", 12, "bold"),
        fieldbackground="#000000",
        background="#000000", 
        foreground="#ec1c3a",
        borderwidth=2,
        relief="solid",
        bordercolor="#ec1c3a",
        selectbackground="#ec1c3a",
        selectforeground="#000000")
    
    style.map("RedCombo.TCombobox",
        fieldbackground=[("readonly", "#000000"), ("focus", "#000000")],
        selectbackground=[("readonly", "#ec1c3a")],
        bordercolor=[("focus", "#ec1c3a")])

    # Buttons
    style.configure("Generate.TButton",
        font=("Consolas", 12, "bold"),
        background="#ec1c3a",
        foreground="#ffffff",
        borderwidth=0,
        focuscolor="none")

    style.configure("Build.TButton", 
        font=("Consolas", 12, "bold"),
        background="#91ddd3",
        foreground="#000000",
        borderwidth=0,
        focuscolor="none")

    style.configure("Copy.TButton",
        font=("Consolas", 12, "bold"), 
        background="#fefe00",
        foreground="#000000",
        borderwidth=0,
        focuscolor="none")
