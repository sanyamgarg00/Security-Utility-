from tkinter import *
from tkinter import messagebox

# Function to encrypt message
def encrypt(message, key):
    ciphertext = ''
    key_idx = 0
    for char in message:
        if char.isalpha():
            char = char.upper()
            shift = ord(key[key_idx % len(key)].upper()) - ord('A')
            cipherchar = chr((ord(char) + shift - 65) % 26 + 65)
            ciphertext += cipherchar
            key_idx += 1
        else:
            ciphertext += char
    return ciphertext

# Function to decrypt message
def decrypt(ciphertext, key):
    message = ''
    key_idx = 0
    for char in ciphertext:
        if char.isalpha():
            char = char.upper()
            shift = ord(key[key_idx % len(key)].upper()) - ord('A')
            plainchar = chr((ord(char) - shift - 65) % 26 + 65)
            message += plainchar
            key_idx += 1
        else:
            message += char
    return message

# Function to handle encryption button press
def encrypt_message():
    key = key_entry.get()
    message = message_entry.get('1.0', END).strip()
    if not key.isnumeric():
        messagebox.showerror("Error", "Key must be an integer")
        return
    ciphertext = encrypt(message, key)
    output_entry.delete('1.0', END)
    output_entry.insert(END, ciphertext)

# Function to handle decryption button press
def decrypt_message():
    key = key_entry.get()
    ciphertext = message_entry.get('1.0', END).strip()
    if not key.isnumeric():
        messagebox.showerror("Error", "Key must be an integer")
        return
    message = decrypt(ciphertext, key)
    output_entry.delete('1.0', END)
    output_entry.insert(END, message)

# Function to copy output to clipboard
import pyperclip

def copy_output():
    output = output_entry.get('1.0', END)
    pyperclip.copy(output)
    messagebox.showinfo("Copy Successful", "Output copied to clipboard")
    
# Main window
root = Tk()
root.title("Cipher Cryptograpy Machine")
root.geometry("400x400")
root.configure(bg="#F2F2F2")

# Key label and entry
key_label = Label(root, text="Key:", font=("Helvetica", 12), bg="#F2F2F2")
key_label.grid(row=1, column=1, padx=10, pady=10)
key_entry = Entry(root, font=("Helvetica", 12))
key_entry.grid(row=1, column=2, padx=10, pady=10)

# Message label and entry
message_label = Label(root, text="Message:", font=("Helvetica", 12), bg="#F2F2F2")
message_entry = Text(root, height=5, width=30, font=("Helvetica", 12))
message_entry.grid(row=2, column=2, padx=10, pady=10)

# Encryption and decryption buttons
encrypt_button = Button(root, text="Encrypt", command=encrypt_message, font=("Helvetica", 12), bg="red", fg="#FFFFFF")
encrypt_button.grid(row=3, column=1, padx=10, pady=10)
decrypt_button = Button(root, text="Decrypt", command=decrypt_message, font=("Helvetica", 12), bg="green", fg="#FFFFFF")
decrypt_button.grid(row=3, column=2, padx=10, pady=20)

# Output label and entry
output_label = Label(root, text="Output:", font=("Helvetica", 12), bg="#F2F2F2")
output_label.grid(row=4, column=1, padx=10, pady=10)
output_entry = Text(root, height=5, width=30)
output_entry.grid(row=4, column=2, padx=10, pady=10)

# Copy output button
copy_button = Button(root, text="Copy Output", command=copy_output, font=("Helvetica", 12))
copy_button.grid(row=5, column=2, padx=10, pady=10)

# Set focus on message entry
message_entry.focus()

# Start GUI event loop
root.mainloop()