import os
import json

# Load a JSON template from file
def load_template(path, key=None):
    if not os.path.exists(path):
        print(f"[!] Template file not found: {path}")
        return {}

    with open(path, "r") as f:
        data = json.load(f)
        return data.get(key, data) if key else data

# Load all templates into a dictionary
def load_template_data():
    template_map = {
        "Shellcode Runner": "templates/Techniques.json",
        "Process Injection": "templates/Techniques.json",
        "Process Hollowing": "templates/Techniques.json"
    }
    
    template_data = {}
    for technique, path in template_map.items():
        if os.path.exists(path):
            key = technique.replace(" ", "")  # e.g., ShellcodeRunner, ProcessInjection
            template_data[technique] = load_template(path, key)
        else:
            print(f"Template file not found: {path}")

    return template_data
