# styles.py

# Function to configure styles for ttk widgets
def configure_styles(style):
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
        foreground="#ec1c3a",
        background="#000000",
        indicatorbackground="#000000",
        selectcolor="#000000"
    )

    # Combobox
    style.configure("RedCombo.TCombobox",
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

    style.map("RedCombo.TCombobox",
        fieldbackground=[("readonly", "#000000")],
        foreground=[("readonly", "#E61C38")],
        background=[("readonly", "#000000")]
    )

    # Entry
    style.configure("RedEntry.TEntry",
        foreground="#E61C38",
        fieldbackground="#000000",
        insertcolor="#E61C38",
        font=("Consolas", 12, "bold")
    )

    # Frames & Buttons
    style.configure("Custom.TFrame", background="#000000")
    style.configure("CopyButton.TButton", font=("Consolas", 15, "bold"))
    style.configure("BuildExe.TButton", font=("Consolas", 15, "bold"))
    style.configure("Generate.TButton", font=("Consolas", 15, "bold"))
    style.configure("OpenFolder.TButton", font=("Consolas", 15, "bold"))
