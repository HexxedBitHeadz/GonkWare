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

# Load shared components from separate files
def load_shared_components():
    """Load common components and features"""
    components = {
        "components": load_template("templates/Components.json"),
        "features": load_template("templates/Features.json"),
        "specialized": load_template("templates/Specialized.json")
    }
    return components

def resolve_inheritance(technique_config, shared_components):
    """Resolve inheritance for a technique configuration"""
    if "inherits" not in technique_config:
        return technique_config
    
    resolved_config = {"code_blocks": technique_config.get("code_blocks", {})}
    inherits = technique_config["inherits"]
    
    # Get component references
    components = shared_components.get("components", {})
    features = shared_components.get("features", {})
    
    # Resolve directives
    resolved_config["directives"] = []
    for directive_group in inherits.get("directives", []):
        if directive_group in components.get("Directives", {}):
            resolved_config["directives"].extend(components["Directives"][directive_group])
    
    # Resolve constants
    resolved_config["constant_declarations"] = []
    for const_group in inherits.get("constants", []):
        if const_group in components.get("Constants", {}):
            resolved_config["constant_declarations"].extend(components["Constants"][const_group])
    
    # Resolve function declarations
    resolved_config["function_declarations"] = []
    for func_group in inherits.get("function_declarations", []):
        if func_group in components.get("FunctionDeclarations", {}):
            resolved_config["function_declarations"].extend(components["FunctionDeclarations"][func_group])
    
    # Resolve function definitions
    resolved_config["function_definitions"] = []
    for func_group in inherits.get("functions", []):
        if func_group in components.get("Functions", {}):
            resolved_config["function_definitions"].extend(components["Functions"][func_group])
    
    # Add structures if needed
    for struct_group in inherits.get("structures", []):
        if struct_group in components.get("Structures", {}):
            resolved_config["function_definitions"].extend(components["Structures"][struct_group])
    
    # Resolve anti-analysis features
    for feature_name in inherits.get("anti_analysis", []):
        if feature_name in features.get("AntiAnalysis", {}):
            resolved_config["code_blocks"][feature_name] = features["AntiAnalysis"][feature_name]
    
    # Resolve obfuscation features
    for feature_name in inherits.get("obfuscation", []):
        if feature_name in features.get("Obfuscation", {}):
            resolved_config["code_blocks"][feature_name] = features["Obfuscation"][feature_name]
    
    # Resolve persistence features
    for feature_name in inherits.get("persistence", []):
        if feature_name in features.get("Persistence", {}):
            resolved_config["code_blocks"][feature_name] = features["Persistence"][feature_name]
    
    return resolved_config

def load_template_data_new():
    """Enhanced template loader with new modular system"""
    # Load shared components
    shared_components = load_shared_components()
    
    # Load main techniques from Core.json
    core_techniques = load_template("templates/Core.json")
    
    # Load specialized techniques  
    specialized = shared_components.get("specialized", {})
    
    template_data = {}
    
    # Process core techniques (C# based)
    for technique_name, technique_config in core_techniques.items():
        display_name = technique_name.replace("Runner", " Runner").replace("Injection", " Injection").replace("Hollowing", " Hollowing")
        resolved_config = resolve_inheritance(technique_config, shared_components)
        template_data[display_name] = resolved_config
    
    # Add specialized techniques (non-C# based)
    for technique_name, technique_config in specialized.items():
        if technique_name in ["VBAMacro", "HTARunner", "CSProjBypass"]:
            display_name = technique_name.replace("CSProjBypass", "csproj msbuild")
            template_data[display_name] = technique_config
    
    # Add AppLocker bypass as a special template for merging
    if "InstallUtilBypass" in specialized:
        template_data["applocker_bypass"] = create_applocker_bypass_template(shared_components)
    
    return template_data

def create_applocker_bypass_template(shared_components):
    """Create AppLocker bypass template from modular components"""
    components = shared_components.get("components", {})
    features = shared_components.get("features", {})
    specialized = shared_components.get("specialized", {})
    
    applocker_template = {}
    
    # Get InstallUtil wrapper structure
    installutil = specialized.get("InstallUtilBypass", {})
    wrapper = installutil.get("class_wrapper", {})
    
    # Build the template
    applocker_template["directives"] = wrapper.get("directives", [])
    
    # Combine function declarations
    applocker_template["function_declarations"] = []
    applocker_template["function_declarations"].extend(components.get("FunctionDeclarations", {}).get("kernel32_basic", []))
    applocker_template["function_declarations"].extend(components.get("FunctionDeclarations", {}).get("kernel32_memory", []))
    applocker_template["function_declarations"].extend(components.get("FunctionDeclarations", {}).get("kernel32_threading", []))
    applocker_template["function_declarations"].extend(components.get("FunctionDeclarations", {}).get("kernel32_process", []))
    applocker_template["function_declarations"].extend(components.get("FunctionDeclarations", {}).get("applocker_bypass", []))
    
    # Add required struct definitions for process functions
    applocker_template["function_definitions"] = []
    applocker_template["function_definitions"].extend(components.get("Structures", {}).get("process_structures", []))
    
    # Add class wrapper info
    applocker_template["class_wrapper"] = wrapper
    
    # Add AppLocker-specific features
    applocker_template["applocker_features"] = features.get("AppLockerBypass", {})
    
    # Add AES decrypt function
    applocker_template["function_definitions"].extend(components.get("Functions", {}).get("aes_decrypt", []))
    
    return applocker_template

def load_template_data():
    """
    Main template loader - uses new modular system
    """
    # Check if new template system files exist
    if (os.path.exists("templates/Core.json") and 
        os.path.exists("templates/Components.json") and 
        os.path.exists("templates/Features.json")):
        print("[+] Using new modular template system")
        return load_template_data_new()
    
    # Fallback to legacy system if new files don't exist
    print("[+] Using legacy template system")
    template_map = {
        "Shellcode Runner": "templates/Techniques.json",
        "Process Injection": "templates/Techniques.json", 
        "Process Hollowing": "templates/Techniques.json"
    }
    
    template_data = {}
    for technique, path in template_map.items():
        if os.path.exists(path):
            key = technique.replace(" ", "")
            template_data[technique] = load_template(path, key)
        else:
            print(f"Template file not found: {path}")

    return template_data
