import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
from tkinter import ttk
from Crypto.Cipher import ChaCha20
import os

# Generate separate secret keys for each user (32 bytes each)
secret_key_1 = os.urandom(32)  # Key for Person #1
secret_key_2 = os.urandom(32)  # Key for Person #2

# Global dictionary to store message nonces and encrypted messages
message_data = {}

# Counter for unique message IDs
message_counter = 0

# Variable to check if encryption is enabled
encryption_enabled = [True]

# Function to encrypt a message with ChaCha20
def encrypt_message(key, message):
    nonce = os.urandom(12)  # Generate a unique nonce for each message
    cipher = ChaCha20.new(key=key, nonce=nonce)
    encrypted_message = cipher.encrypt(message.encode("utf-8"))
    return nonce + encrypted_message  # Return nonce and encrypted message

# Function to decrypt a message with ChaCha20 using a provided key and nonce
def decrypt_message(key, nonce, encrypted_data):
    try:
        cipher = ChaCha20.new(key=key, nonce=nonce)
        decrypted_message = cipher.decrypt(encrypted_data)
        return decrypted_message.decode("utf-8")
    except Exception:
        return "Decryption Failed: Incorrect Key or Nonce"

# Function to send a message from one window to another, with optional encryption
def send_message(entry_field, sender_display, receiver_display, key, encryption_enabled):
    global message_counter
    message = entry_field.get()
    if not message:
        return  # No message to send

    # Increment message counter to get a unique ID
    message_id = message_counter
    message_counter += 1

    if encryption_enabled[0]:
        # Encrypt the message with the provided key
        encrypted_message = encrypt_message(key, message)
        nonce = encrypted_message[:12]  # Get the nonce used
        
        # Store the nonce and encrypted data with the message ID
        message_data[message_id] = {
            "nonce": nonce,
            "encrypted": encrypted_message[12:]
        }

        # Display the encrypted message in the receiver's display area with the ID
        receiver_display.insert(tk.END, f"Message {message_id} (Encrypted): {encrypted_message[12:].hex()}\n")
    else:
        # If encryption is not enabled, just send the plain text
        receiver_display.insert(tk.END, f"You: {message}\n")

    # Display the original message in the sender's display area
    sender_display.insert(tk.END, f"You: {message}\n")

    # Clear the entry field
    entry_field.delete(0, tk.END)

# Function to display the nonce for a specific message ID and copy to clipboard
def display_nonce():
    message_id = simpledialog.askinteger("Enter Message ID", "Enter the message ID to get its nonce:")
    if message_id is not None:
        nonce = message_data.get(message_id, {}).get("nonce")
        if nonce is not None:
            # Copy the nonce to the clipboard
            root.clipboard_clear()
            root.clipboard_append(nonce.hex())
            messagebox.showinfo("Nonce Information", f"Nonce for message {message_id}: {nonce.hex()} (Nonce copied to clipboard)")
        else:
            messagebox.showwarning("No Nonce Found", f"No nonce found for message {message_id}.")
    else:
        messagebox.showwarning("Invalid Input", "Please enter a valid message ID.")

# Function to decrypt a message using a custom key, nonce, and encrypted data from a given message ID
def decrypt_message_by_id(display_area):
    message_id = simpledialog.askinteger("Enter Message ID", "Enter the message ID to decrypt:")
    if message_id is not None:
        message_info = message_data.get(message_id)
        if message_info:
            nonce = message_info["nonce"]
            encrypted_data = message_info["encrypted"]
            
            # Ask the user for a custom key for decryption
            custom_key_hex = simpledialog.askstring("Enter Key", "Enter the key in hexadecimal:")
            if custom_key_hex:
                try:
                    custom_key = bytes.fromhex(custom_key_hex)
                    decrypted_message = decrypt_message(custom_key, nonce, encrypted_data)
                    # Display the decrypted message
                    display_area.insert(tk.END, f"Decrypted (Message {message_id}): {decrypted_message}\n")
                except ValueError:
                    messagebox.showerror("Invalid Key", "The provided key is not valid hexadecimal.")
            else:
                messagebox.showwarning("Key Required", "A valid key is required to decrypt the message.")
        else:
            messagebox.showwarning("Invalid Message ID", "No data found for the given message ID.")
    else:
        messagebox.showwarning("Invalid Input", "Please enter a valid message ID.")

# Create the secondary window with text entry and decryption
def create_secondary_window(parent):
    secondary_window = tk.Toplevel(parent)
    secondary_window.title("Person #2")
    secondary_window.geometry("450x550")

    # Scrolled text area to display messages
    display_area = scrolledtext.ScrolledText(secondary_window, wrap=tk.WORD, width=50, height=25)
    display_area.pack(pady=20)

    # Text entry field with a send button at the bottom
    bottom_frame = ttk.Frame(secondary_window)
    bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

    text_entry = ttk.Entry(bottom_frame, width=25)
    text_entry.pack(side=tk.LEFT, padx=5)

    # The send button sends messages to the main window's display area
    send_button = ttk.Button(
        bottom_frame, text="Send", command=lambda: send_message(text_entry, display_area, display_area_main, secret_key_2, encryption_enabled)
    )
    send_button.pack(side=tk.RIGHT)

    # Button to display nonce for a specific message and copy to clipboard
    nonce_display_button = ttk.Button(
        bottom_frame,
        text="Display Nonce",
        command=display_nonce
    )
    nonce_display_button.pack(side=tk.RIGHT)

    # Button to display and copy the current secret key for the secondary window
    key_display_button = ttk.Button(
        bottom_frame,
        text="Display Key",
        command=lambda: (
            secondary_window.clipboard_clear() or
            secondary_window.clipboard_append(secret_key_2.hex()) or
            messagebox.showinfo("Current Key", f"Current Key: {secret_key_2.hex()} (Key copied to clipboard)")
        )
    )
    key_display_button.pack(side=tk.RIGHT)

    # Button to input a custom key and nonce to decrypt messages
    decrypt_button = ttk.Button(
        bottom_frame, text="Decrypt", command=lambda: decrypt_message_by_id(display_area)
    )
    decrypt_button.pack(side=tk.RIGHT)

    return display_area

# Create the main application window (Person #1)
root = tk.Tk()
root.title("Person #1")
root.geometry("450x550")

# Scrolled text area to display messages in the main window
display_area_main = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=45, height=25)
display_area_main.pack(pady=20)

# Text entry field with a send button at the bottom of the main window
bottom_frame_main = ttk.Frame(root)
bottom_frame_main.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

text_entry_main = ttk.Entry(bottom_frame_main, width=25)
text_entry_main.pack(side=tk.LEFT, padx=5)

# The send button sends messages to the secondary window's display area
send_button_main = ttk.Button(
    bottom_frame_main, text="Send", command=lambda: send_message(text_entry_main, display_area_main, display_area_secondary, secret_key_1, encryption_enabled)
)
send_button_main.pack(side=tk.RIGHT)

# Button to display and copy the current secret key for the main window
key_display_button_main = ttk.Button(
    bottom_frame_main,
    text="Display Key",
        command=lambda: (
            root.clipboard_clear() or
            root.clipboard_append(secret_key_1.hex()) or
            messagebox.showinfo("Current Key", f"Current Key: {secret_key_1.hex()} (Key copied to clipboard)")
        )
)
key_display_button_main.pack(side=tk.RIGHT)

# Button to display nonce for a specific message and copy to clipboard in the main window
nonce_display_button_main = ttk.Button(
    bottom_frame_main, text="Display Nonce", command=display_nonce
)
nonce_display_button_main.pack(side=tk.RIGHT)

# Button to decrypt messages by message ID in the main window
decrypt_button_main = ttk.Button(
    bottom_frame_main, text="Decrypt", command=lambda: decrypt_message_by_id(display_area_main)
)
decrypt_button_main.pack(side=tk.RIGHT)

# Create the secondary window
display_area_secondary = create_secondary_window(root)

# Run the Tkinter event loop
root.mainloop()
