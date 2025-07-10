import os, subprocess, random, glob
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from PIL import Image, ImageTk
from core.layout import create_base_layout, create_left_right_controls, create_status_controls, update_generation_state, setup_output_display, resize_center_bg, bind_dynamic_bg_resize
from core.template_loader import load_template_data
from core.styles import configure_styles
from core.utils import update_msf_entry


# Main Application Class
class GonkWareApp:
    def __init__(self, root):
        self.root = root
        root.title("Hexxed BitHeadz - GonkWare Alpha build")
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
        configure_styles(self.style)

        self.template_data = load_template_data()

        self.create_frames()

    # Create frames and layout
    def create_frames(self):
        layout_refs = create_base_layout(self.root)

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

        create_left_right_controls(self)

        create_status_controls(self)
        bind_dynamic_bg_resize(self) # resizing background images when window is resized

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
        print("Selected template: " + technique_key)
        
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
        base_image = base_image.resize((64, 64))

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