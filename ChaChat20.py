import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
from tkinter import ttk
from Crypto.Cipher import ChaCha20
import os

# Default secret key for ChaCha20 (32 bytes)
DEFAULT_SECRET_KEY = os.urandom(32)

# Function to encrypt a message with ChaCha20
def encrypt_message(key, message):
    nonce = os.urandom(12)  # Generate a unique nonce for each message
    cipher = ChaCha20.new(key=key, nonce=nonce)
    encrypted_message = cipher.encrypt(message.encode("utf-8"))
    return nonce + encrypted_message  # Return nonce and encrypted message

# Function to decrypt a message with ChaCha20 using a provided key
def decrypt_message(key, encrypted_data):
    try:
        nonce = encrypted_data[:12]  # Extract the nonce from the encrypted data
        encrypted_message = encrypted_data[12:]  # The actual encrypted message
        cipher = ChaCha20.new(key=key, nonce=nonce)
        decrypted_message = cipher.decrypt(encrypted_message)
        return decrypted_message.decode("utf-8")
    except Exception:
        return "Decryption Failed: Incorrect Key"

# Function to send an encrypted message from one window to another
def send_message(entry_field, sender_display, receiver_display, key):
    message = entry_field.get()
    if message:
        # Encrypt the message with the provided key
        encrypted_message = encrypt_message(key, message)

        # Display the encrypted message in the sender's display area
        sender_display.insert(tk.END, f"You (Encrypted): {encrypted_message.hex()}\n")

        # Try to decrypt the message with the provided key for display in the receiver's display area
        decrypted_message = decrypt_message(key, encrypted_message)
        receiver_display.insert(tk.END, f"Other: {decrypted_message}\n")

        # Clear the entry field
        entry_field.delete(0, tk.END)

# Function to create a secondary window with text entry and decryption
def create_secondary_window(parent, default_key):
    secondary_window = tk.Toplevel(parent)
    secondary_window.title("Person #2")
    secondary_window.geometry("300x250")

    # Variable to hold the secret key
    secret_key = [default_key]  # Using a list to allow modification within the closure

    # Scrolled text area to display messages
    display_area = scrolledtext.ScrolledText(secondary_window, wrap=tk.WORD, width=30, height=10)
    display_area.pack(pady=20)

    # Text entry field with a send button at the bottom
    bottom_frame = ttk.Frame(secondary_window)
    bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

    text_entry = ttk.Entry(bottom_frame, width=25)
    text_entry.pack(side=tk.LEFT, padx=5)

    # The send button sends encrypted messages to the main window's display area
    send_button = ttk.Button(
        bottom_frame, text="Send", command=lambda: send_message(text_entry, display_area, display_area_main, secret_key[0])
    )
    send_button.pack(side=tk.RIGHT)

    # Add a button to input a custom key
    key_input_button = ttk.Button(
        bottom_frame,
        text="Input Key",
        command=lambda: secret_key.__setitem__(0, bytes.fromhex(simpledialog.askstring("Input Key", "Enter key in hex:"))),
    )
    key_input_button.pack(side=tk.RIGHT)

    # Add a button to display the current secret key
    key_display_button = ttk.Button(
        bottom_frame,
        text="Display Key",
        command=lambda: messagebox.showinfo("Current Key", f"Current Key: {secret_key[0].hex()}"),
    )
    key_display_button.pack(side=tk.RIGHT)

    return display_area

# Create the main application window (Person #1)
root = tk.Tk()
root.title("Person #1")
root.geometry("300x250")

# Scrolled text area to display messages in the main window
display_area_main = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=30, height=10)
display_area_main.pack(pady=20)

# Variable to hold the key for this window
main_secret_key = [DEFAULT_SECRET_KEY]

# Text entry field with a send button at the bottom of the main window
bottom_frame_main = ttk.Frame(root)
bottom_frame_main.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

text_entry_main = ttk.Entry(bottom_frame_main, width=25)
text_entry_main.pack(side=tk.LEFT, padx=5)

# The send button sends encrypted messages to the secondary window's display area
send_button_main = ttk.Button(
    bottom_frame_main, text="Send", command=lambda: send_message(text_entry_main, display_area_main, display_area_secondary, main_secret_key[0])
)
send_button_main.pack(side=tk.RIGHT)

# Add a button to input a custom key
key_input_button_main = ttk.Button(
    bottom_frame_main,
    text="Input Key",
    command=lambda: main_secret_key.__setitem__(0, bytes.fromhex(simpledialog.askstring("Input Key", "Enter key in hex:"))),
)
key_input_button_main.pack(side=tk.RIGHT)

# Add a button to display the current secret key
key_display_button_main = ttk.Button(
    bottom_frame_main,
    text="Display Key",
    command=lambda: messagebox.showinfo("Current Key", f"Current Key: {main_secret_key[0].hex()}"),
)
key_display_button_main.pack(side=tk.RIGHT)

# Create the secondary window
display_area_secondary = create_secondary_window(root, DEFAULT_SECRET_KEY)

# Run the Tkinter event loop
root.mainloop()
