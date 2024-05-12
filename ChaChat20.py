import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
from tkinter import ttk
from Crypto.Cipher import ChaCha20
from datetime import datetime
import pandas as pd 
import os

# Sample user data with hashed passwords for simplicity (in a real application, store passwords securely)
user_data = {
    "user1": "password1",
    "user2": "password2"
}

# Generate separate secret keys for each user (32 bytes each)
secret_key_1 = os.urandom(32)  # Key for Person #1
secret_key_2 = os.urandom(32)  # Key for Person #2

message_data = {}

message_counter = 1

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

def send_message(entry_field, sender_display, receiver_display, key, encryption_enabled, sender):
    global message_counter
    message = entry_field.get()

    if not message:
        return  # No message to send

    message_id = message_counter
    message_counter += 1

    if encryption_enabled[0]:
        encrypted_message = encrypt_message(key, message)
        nonce = encrypted_message[:12]  # Get the nonce used

        message_data[message_id] = {
        "sender": sender,
        "nonce": nonce,
        "encrypted": encrypted_message[12:]
    }

        receiver_display.insert(
            tk.END,
            f"Person[{message_id}] (Encrypted): {encrypted_message[12:].hex()}\n",
            "other",
        )
    else:
        receiver_display.insert(tk.END, f"You: {message}\n", "other")

    sender_display.insert(tk.END, f"You: {message}\n", "you")

    entry_field.delete(0, tk.END)


# Function to display the nonce for a specific message ID and copy to clipboard
def display_nonce(root):
   message_id = simpledialog.askinteger("Enter Message ID", "Enter the message ID to get its nonce:")
   if message_id is not None:
       nonce = message_data.get(message_id, {}).get("nonce")
       if nonce is not None:
           root.clipboard_clear()
           root.clipboard_append(nonce.hex())
           messagebox.showinfo("Nonce Information",
                               f"Nonce for message {message_id}: {nonce.hex()} (Nonce copied to clipboard)")
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
                    # Display the decrypted message with 'decrypted' text tag
                    display_area.insert(tk.END, f"Other[{message_id}] (Decrypted): {decrypted_message}\n", "decrypted")
                except ValueError:
                    messagebox.showerror("Invalid Key", "The provided key is not valid hexadecimal.")
            else:
                messagebox.showwarning("Key Required", "A valid key is required to decrypt the message.")
        else:
            messagebox.showwarning("Invalid Message ID", "No data found for the given message ID.")
    else:
        messagebox.showwarning("Invalid Input", "Please enter a valid message ID.")

# Login class to authenticate users before accessing the main window
class LoginWindow(tk.Toplevel):
    def __init__(self, parent, on_success_callback):
        super().__init__(parent)
        self.title("Login")
        self.geometry("300x150")
        self.on_success_callback = on_success_callback

        ttk.Label(self, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(self)
        self.username_entry.pack(pady=5)

        ttk.Label(self, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(self, show="*")
        self.password_entry.pack(pady=5)

        ttk.Button(self, text="Login", command=self.login).pack(pady=5)

        self.bind("<Return>", lambda event: self.login())  # Login on Enter key press

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username in user_data and user_data[username] == password:
            self.destroy()  # Close the login window
            self.on_success_callback()  # Call the success callback to open the main window
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

# Create the secondary window with text entry and decryption
def create_secondary_window(parent, display_area_main):
   secondary_window = tk.Toplevel(parent)
   secondary_window.title("Person #2")
   secondary_window.geometry("500x482")


   # Scrolled text area to display messages
   display_area = scrolledtext.ScrolledText(secondary_window, wrap=tk.WORD, width=56, height=25)
   # Add text tags for different users
   display_area.tag_config("you", foreground="blue")
   display_area.tag_config("other", foreground="green")
   display_area.tag_config("decrypted", foreground="orange")
   display_area.tag_config("status", foreground="purple")
   display_area.tag_config("bold", font="Courier 12 bold")


   display_area.insert(tk.END,
                       "Instructions:\n1. Use the 'Send' button to send messages.\n2. Use the 'Decrypt' button to decrypt messages.\n3. Use the 'Display Nonce' button to view nonces.\n4. Use the 'Display Key' button to view the current key.\n",
                       "bold")
   display_area.pack(pady=10)


   bottom_frame = ttk.Frame(secondary_window)
   bottom_frame.pack(fill=tk.X, padx=10, pady=10)


   text_entry = ttk.Entry(bottom_frame, width=25)
   text_entry.pack(side=tk.LEFT, padx=5)
   text_entry.bind("<Return>", lambda event: send_message(text_entry, display_area, display_area_main, secret_key_2,
                                                          encryption_enabled, sender = 2))


   send_button = ttk.Button(
       bottom_frame, text="Send",
       command=lambda: send_message(text_entry, display_area, display_area_main, secret_key_2, encryption_enabled, sender = 2)
   )
   send_button.pack(side=tk.LEFT)


   nonce_display_button = ttk.Button(
       bottom_frame,
       text="Display Nonce",
       command=lambda: display_nonce(parent)
   )
   nonce_display_button.pack(side=tk.RIGHT)


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


   decrypt_button = ttk.Button(
       bottom_frame, text="Decrypt", command=lambda: decrypt_message_by_id(display_area)
   )
   decrypt_button.pack(side=tk.RIGHT)

   return display_area

# Create the main window after successful login
def open_main_window():
    root = tk.Tk()
    root.title("Person #1")
    root.geometry("500x482")

    display_area_main = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=56, height=25)
    display_area_main.tag_config("you", foreground="blue")
    display_area_main.tag_config("other", foreground="green")
    display_area_main.tag_config("decrypted", foreground="orange")
    display_area_main.tag_config("status", foreground="purple")
    display_area_main.tag_config("bold", font="Courier 12 bold")

    display_area_main.insert(tk.END,
                             "Instructions:\n1. Use the 'Send' button to send messages.\n2. Use the 'Decrypt' button to decrypt messages.\n3. Use the 'Display Nonce' button to view nonces.\n4. Use the 'Display Key' button to view the current key.\n",
                             "bold")
    display_area_main.pack(pady=10)

    bottom_frame_main = ttk.Frame(root)
    bottom_frame_main.pack(fill=tk.X, padx=10, pady=10)

    text_entry_main = ttk.Entry(bottom_frame_main, width=25)
    text_entry_main.pack(side=tk.LEFT, padx=5)
    text_entry_main.bind("<Return>", lambda event: send_message(text_entry_main, display_area_main, display_area_secondary, secret_key_1, encryption_enabled, sender=1))

    send_button_main = ttk.Button(
        bottom_frame_main, text="Send", command=lambda: send_message(text_entry_main, display_area_main, display_area_secondary, secret_key_1, encryption_enabled, sender = 1)
    )
    send_button_main.pack(side=tk.LEFT)

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

    nonce_display_button_main = ttk.Button(
        bottom_frame_main, text="Display Nonce", command=lambda: display_nonce(root)
    )
    nonce_display_button_main.pack(side=tk.RIGHT)

    decrypt_button_main = ttk.Button(
        bottom_frame_main, text="Decrypt", command=lambda: decrypt_message_by_id(display_area_main)
    )
    decrypt_button_main.pack(side=tk.RIGHT)

    display_area_secondary = create_secondary_window(root, display_area_main)

    # Connect the on_closing function to the main window's closing event
    root.protocol("WM_DELETE_WINDOW", lambda: on_closing(root))

    root.mainloop()

from datetime import datetime

def on_closing(root):
    print("Closing window...")
    # Get current date and time
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    # Construct Excel file name with current date and time
    excel_file_name = f"messages_{current_datetime}.xlsx"
    # Convert message_data to DataFrame including message content and sender
    df = pd.DataFrame.from_dict(message_data, orient='index', columns=['sender', 'encrypted'])
    # Include the message content in the DataFrame
    df['message'] = [decrypt_message(secret_key_1, message_info["nonce"], message_info["encrypted"]) if message_info["sender"] == 1 else decrypt_message(secret_key_2, message_info["nonce"], message_info["encrypted"]) for message_info in message_data.values()]
    # Remove any rows where decryption failed
    df = df[df['message'] != "Decryption Failed: Incorrect Key or Nonce"]
    # Export DataFrame to Excel file with current date and time in the name
    df.to_excel(excel_file_name, index_label='message_id')
    print(f"Excel file saved as {excel_file_name}.")
    root.destroy()  # Close the window

# Start the application with a login window
root_login = tk.Tk()
root_login.withdraw()  # Hide the initial window
login_window = LoginWindow(root_login, open_main_window)
login_window.mainloop()
