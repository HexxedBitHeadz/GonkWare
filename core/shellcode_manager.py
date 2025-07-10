import threading
import ttkbootstrap as tb
from core.builder import generate_shellcode_backend, build_final_script

# Generate shellcode in a separate thread to keep the GUI responsive
def generate_shellcode_threaded(app, update_status_fn):
    update_status_fn(app, enabled=False)
    app.start_glitch_animation()

    if app.marquee_job:
        app.root.after_cancel(app.marquee_job)
        app.marquee_job = None

    app.top_status_label.config(text="Shellcode")
    app.output_text.configure(state="normal")
    app.output_text.delete("1.0", tb.END)
    app.output_text.configure(state="disabled")

    thread = threading.Thread(
        target=threaded_shellcode_generate,
        args=(app, update_status_fn)
    )
    thread.start()

# Actual shellcode generation logic
def threaded_shellcode_generate(app, update_status_fn):
    try:
        selected_format = app.selected_format.get()
        arch = app.architecture.get()
        payload = app.payload_type.get()
        connection = app.selected_connection.get()
        interface = app.selected_interface.get()
        port = app.port.get()
        template = app.get_selected_template()

        # Generate raw shellcode only
        _, shellcode_only, _ = generate_shellcode_backend(
            selected_format, arch, payload, connection, interface, port, template
        )

        print("Template:", template)
        print("Shellcode length:", len(shellcode_only))

        # Build final script with AES applied internally
        final_script = build_final_script(
            template=template,
            shellcode=shellcode_only
        )

        print("Final script:", "None" if final_script is None else "Generated")

        msf_cmd = app.build_msfconsole_cmd()
        app.root.after(0, lambda: finish_shellcode_generate(app, final_script, shellcode_only, msf_cmd, update_status_fn))

    except Exception as e:
        app.root.after(0, lambda: app.output_text.insert(tb.END, f"\n[!] Error: {str(e)}"))
        app.root.after(0, lambda: update_status_fn(app, enabled=True))

# Finalize the GUI updates after shellcode generation
def finish_shellcode_generate(app, script, shellcode_only, msf_cmd, update_status_fn):
    app.shellcode_only = shellcode_only
    app.original_shellcode = script
    app.full_msf_cmd = msf_cmd

    app.render_script(script)

    app.msf_entry.configure(
        state="normal",
        foreground="#000000",
        background="#FEFE00",
        insertbackground="#000000"
    )
    app.msf_entry.delete("1.0", tb.END)
    app.msf_entry.insert("1.0", msf_cmd)
    app.msf_entry.configure(state="disabled")

    app.copy_button.configure(state=tb.NORMAL)
    app.build_button.configure(state=tb.NORMAL)
    
    # Enable applocker checkbox after code is generated
    if hasattr(app, 'applocker_checkbox'):
        app.applocker_checkbox.configure(state=tb.NORMAL)

    app.start_marquee()
    app.loading_image_label.place_forget()
    app.stop_glitch_animation()

    update_status_fn(
        app,
        enabled=True,
        top_text="Shellcode",
        bottom_text="Generated",
        color="#00ff00"
    )
