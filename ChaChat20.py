import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk
from tkinter import simpledialog

# Function to send a message from one window to another, using the given names
def send_message(entry_field, sender_display, receiver_display, sender_name, receiver_name):
    message = entry_field.get()
    if message:
        # Display the message in the sender's display area with their name
        sender_display.insert(tk.END, f"{sender_name}: {message}\n")
        
        # Display the message in the receiver's display area with their name
        receiver_display.insert(tk.END, f"{receiver_name}: {message}\n")
        
        # Clear the entry field
        entry_field.delete(0, tk.END)

# Function to create a secondary window with a text entry field
def create_secondary_window(parent, display_area_main, name1, name2):
    secondary_window = tk.Toplevel(parent)  # This ensures it's not a main window
    secondary_window.title(name2)
    secondary_window.geometry("300x200")

    # Scrolled text area to display messages
    display_area = scrolledtext.ScrolledText(secondary_window, wrap=tk.WORD, width=30, height=10)
    display_area.pack(pady=20)

    # Text entry field with a send button at the bottom
    bottom_frame = ttk.Frame(secondary_window)
    bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

    text_entry = ttk.Entry(bottom_frame, width=25)
    text_entry.pack(side=tk.LEFT, padx=5)

    # The send button sends messages to the main window's display area
    send_button = ttk.Button(bottom_frame, text="Send", command=lambda: send_message(text_entry, display_area, display_area_main, name2, name1))
    send_button.pack(side=tk.RIGHT)

    return display_area

# Create the main application window and get user names
root = tk.Tk()  # Main window must be a single Tk instance

# Ask for the names of the two people before creating the windows
person1_name = simpledialog.askstring("Name", "Enter the name of Person 1:")
person2_name = simpledialog.askstring("Name", "Enter the name of Person 2:")

# Use the entered names to title the windows
root.title(person1_name)
root.geometry("300x200")

# Scrolled text area to display messages in the main window
display_area_main = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=30, height=10)
display_area_main.pack(pady=20)

# Automatically create the secondary window with the names
display_area_secondary = create_secondary_window(root, display_area_main, person1_name, person2_name)

# Text entry field with a send button at the bottom of the main window
bottom_frame = ttk.Frame(root)
bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

text_entry = ttk.Entry(bottom_frame, width=25)
text_entry.pack(side=tk.LEFT, padx=5)

# The send button in the main window sends messages to the secondary window's display area
send_button = ttk.Button(bottom_frame, text="Send", command=lambda: send_message(text_entry, display_area_main, display_area_secondary, person1_name, person2_name))
send_button.pack(side=tk.RIGHT)

# Run the Tkinter event loop
root.mainloop()
