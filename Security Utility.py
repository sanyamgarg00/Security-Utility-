import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from socket import *
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import requests
import random
import string
import threading
import pyperclip
from tkinter import messagebox
from tkinter import END


class Home:
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(self.parent)
        self.frame.pack(fill="both", expand=True)

        self.description_label = ttk.Label(
            self.frame,
            text="Welcome To The Security Utility Program!",
            font=("Arial", 22, "bold"),
            anchor="center",
            justify="center"
        )
        self.description_label.place(relx=0.5, rely=0.4, anchor="center")

        self.instructions_label = ttk.Label(
            self.frame,
            text="Select A Tab Above To Access\n The Different Tools",
            font=("Arial", 18),
            anchor="center",
            justify="center"
        )
        self.instructions_label.place(relx=0.5, rely=0.6, anchor="center")

class PasswordGenerator:
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(self.parent)
        self.frame.pack()

        self.label = ttk.Label(self.frame, text="Password Generator", font=("Arial", 22, "bold"))
        self.label.pack(pady=20)

        self.password_length_label = ttk.Label(self.frame, text="Password Length", font=("Arial", 16, "bold"))
        self.password_length_label.pack()

        self.password_length_entry = ttk.Entry(self.frame, width=30)
        self.password_length_entry.pack(pady=10)

        self.password_strength_label = ttk.Label(self.frame, text="Password Strength:", font=("Arial", 16, "bold"))
        self.password_strength_label.pack()

        self.password_strength_var = tk.StringVar()
        self.password_strength_var.set("Easy")

        radio_button_style = ttk.Style()
        radio_button_style.configure("TRadiobutton", font=("Arial", 16, "bold"))

        self.easy_radio = ttk.Radiobutton(self.frame, text="Easy", variable=self.password_strength_var, value="Easy", style="TRadiobutton")
        self.easy_radio.pack()

        self.medium_radio = ttk.Radiobutton(self.frame, text="Medium", variable=self.password_strength_var, value="Medium", style="TRadiobutton")
        self.medium_radio.pack()

        self.hard_radio = ttk.Radiobutton(self.frame, text="Hard", variable=self.password_strength_var, value="Hard", style="TRadiobutton")
        self.hard_radio.pack()

        button_style = ttk.Style()
        button_style.configure("TButton", font=("Arial", 16, "bold"))

        self.generate_button = ttk.Button(self.frame, text="Generate Password", command=self.generate_password, style="TButton")
        self.generate_button.pack(pady=10)

        self.generated_password_entry = ttk.Entry(self.frame, width=30)
        self.generated_password_entry.pack()

        self.copy_button = ttk.Button(self.frame, text="Copy Password", command=self.copy_password, style="TButton")
        self.copy_button.pack(pady=10)

        entry_style = ttk.Style()
        entry_style.configure("TEntry", padding=(0, 5))  # Adjust the padding for the TEntry style

        self.password_length_entry.configure(style="TEntry")
        self.generated_password_entry.configure(style="TEntry")

    def generate_password(self):
        password_length = int(self.password_length_entry.get())
        password_strength = self.password_strength_var.get()

        if password_strength == "Easy":
            characters = string.ascii_letters
        elif password_strength == "Medium":
            characters = string.ascii_letters + string.digits
        else:  # Hard
            characters = string.ascii_letters + string.digits + string.punctuation

        password = ''.join(random.choice(characters) for _ in range(password_length))
        self.generated_password_entry.delete(0, tk.END)
        self.generated_password_entry.insert(0, password)

    def copy_password(self):
        password = self.generated_password_entry.get()
        pyperclip.copy(password)


class CipherCryptographicMachine:
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(self.parent)
        self.frame.pack()

        self.label = ttk.Label(self.frame, text="Cipher Cryptographic Machine", font=("Arial", 22, "bold"))
        self.label.grid(row=0, column=0, columnspan=4, pady=20, sticky='n')

        self.plaintext_label = ttk.Label(self.frame, text="Plain Text", font=("Arial", 16, "bold"))
        self.plaintext_label.grid(row=1, column=0, pady=10)

        self.plaintext_entry = ttk.Entry(self.frame, width=30)
        self.plaintext_entry.grid(row=1, column=1, pady=20)

        self.plaintext_copy_button = ttk.Button(self.frame, text="Copy", command=self.copy_plain_text)
        self.plaintext_copy_button.grid(row=1, column=2, padx=5, pady=20)

        self.plaintext_clear_button = ttk.Button(self.frame, text="Clear", command=self.clear_plain_text)
        self.plaintext_clear_button.grid(row=1, column=3, padx=5, pady=20)

        self.key_label = ttk.Label(self.frame, text="Cipher Key", font=("Arial", 16, "bold"))
        self.key_label.grid(row=2, column=0, pady=10)

        self.key_entry = ttk.Entry(self.frame, width=30)
        self.key_entry.grid(row=2, column=1, pady=20)

        self.ciphertext_label = ttk.Label(self.frame, text="Cipher Text", font=("Arial", 16, "bold"))
        self.ciphertext_label.grid(row=3, column=0, pady=20)

        self.ciphertext_entry = ttk.Entry(self.frame, width=30)
        self.ciphertext_entry.grid(row=3, column=1, pady=20)

        self.ciphertext_copy_button = ttk.Button(self.frame, text="Copy", command=self.copy_cipher_text)
        self.ciphertext_copy_button.grid(row=3, column=2, padx=5, pady=20)

        self.ciphertext_clear_button = ttk.Button(self.frame, text="Clear", command=self.clear_cipher_text)
        self.ciphertext_clear_button.grid(row=3, column=3, padx=5, pady=20)

        self.encrypt_button = ttk.Button(self.frame, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=4, column=0, padx=5, pady=20)

        self.decrypt_button = ttk.Button(self.frame, text="Decrypt", command=self.decrypt)
        self.decrypt_button.grid(row=4, column=1, padx=5, pady=20)

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

    def encrypt(self):
        message = self.plaintext_entry.get()
        key = self.key_entry.get()
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
        self.ciphertext_entry.delete(0, 'end')
        self.ciphertext_entry.insert(0, ciphertext)

    def decrypt(self):
        ciphertext = self.ciphertext_entry.get()
        key = self.key_entry.get()
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
        self.plaintext_entry.delete(0, 'end')
        self.plaintext_entry.insert(0, message)

    def encrypt_message(self):
        key = self.key_entry.get()
        message = self.plaintext_entry.get()
        if not key.isnumeric():
            messagebox.showerror("Error", "Key must be an integer")
            return
        ciphertext = self.encrypt()
        self.ciphertext_entry.delete(0, 'end')
        self.ciphertext_entry.insert(0, ciphertext)

    def decrypt_message(self):
        key = self.key_entry.get()
        ciphertext = self.ciphertext_entry.get()
        if not key.isnumeric():
            messagebox.showerror("Error", "Key must be an integer")
            return
        plaintext = self.decrypt()
        self.plaintext_entry.delete(0, 'end')
        self.plaintext_entry.insert(0, plaintext)

    def copy_plain_text(self):
        plain_text = self.plaintext_entry.get()
        pyperclip.copy(plain_text)

    def copy_cipher_text(self):
        cipher_text = self.ciphertext_entry.get()
        pyperclip.copy(cipher_text)    

    def clear_plain_text(self):
        self.plaintext_entry.delete(0, 'end')

    def clear_cipher_text(self):
        self.ciphertext_entry.delete(0, 'end')    

class PortScanner:
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(self.parent)
        self.frame.pack()

        self.label = ttk.Label(self.frame, text="Port Scanner", font=("Arial", 22, "bold"))
        self.label.grid(row=0, column=0, columnspan=2, pady=10)

        self.ip_label = ttk.Label(self.frame, text="Enter IP Address:", font=("Arial", 16, "bold"))
        self.ip_label.grid(row=1, column=0, sticky=tk.E, pady=10)

        self.ip_entry = ttk.Entry(self.frame)
        self.ip_entry.grid(row=1, column=1, pady=10)

        self.ports_label = ttk.Label(self.frame, text="Enter Port Range:", font=("Arial", 16, "bold"))
        self.ports_label.grid(row=2, column=0, sticky=tk.E, pady=10)

        self.ports_entry = ttk.Entry(self.frame)
        self.ports_entry.grid(row=2, column=1)

        self.scan_button = ttk.Button(self.frame, text="Scan Ports", command=self.scan_ports)
        self.scan_button.grid(row=3, column=0, pady=10)

        self.stop_button = ttk.Button(self.frame, text="Stop Scan", command=self.stop_scan)
        self.stop_button.grid(row=3, column=1, pady=10, padx=5)

        self.results_text = ScrolledText(self.frame, width=40, height=10)
        self.results_text.grid(row=4, column=0, columnspan=2)

    def clear_results(self):
        self.results_text.delete("1.0", tk.END)

    def scan_ports(self):
        self.clear_results()

        target = self.ip_entry.get()
        port_range = self.ports_entry.get().split("-")

        if len(port_range) != 2:
            self.results_text.insert(tk.END, "Invalid port range.")
            return

        try:
            start_port = int(port_range[0])
            end_port = int(port_range[1])
        except ValueError:
            self.results_text.insert(tk.END, "Invalid port range.")
            return

        self.results_text.insert(tk.END, f"Scanning ports {start_port}-{end_port}...\n")

        t = threading.Thread(target=self.do_scan, args=(target, start_port, end_port))
        t.start()

    def do_scan(self, target, start_port, end_port):
        for port in range(start_port, end_port + 1):
            s = socket(AF_INET, SOCK_STREAM)
            s.settimeout(1)

            try:
                conn = s.connect_ex((target, port))
                if conn == 0:
                    self.results_text.insert(tk.END, f"Port {port}: OPEN\n")
                s.close()
            except:
                pass

        self.results_text.insert(tk.END, "Scan complete.")

    def stop_scan(self):
        self.scan_running = False
        self.results_text.insert(tk.END, "Scan stopped.")    

class SQLInjectionScanner:
    
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(self.parent)
        self.frame.pack()

        self.label = ttk.Label(self.frame, text="SQL Injection Vulnerability Scanner", font=("Arial", 22, "bold"))
        self.label.pack(pady=10)

        self.url_label = ttk.Label(self.frame, text="Enter the Website URL", font=("Arial", 16, "bold"))
        self.url_label.pack()

        self.url_entry = ttk.Entry(self.frame, width=30)
        self.url_entry.pack(pady=5)

        self.scan_button = ttk.Button(self.frame, text="Scan", command=self.sql_injection_scan)
        self.scan_button.pack(pady=20)

        self.results_text = ScrolledText(self.frame, width=40, height=10)
        self.results_text.pack()

    def clear_results(self):
        self.results_text.delete("1.0", tk.END)

    def get_forms(self, url):
        soup = BeautifulSoup(requests.get(url).content, "html.parser")
        return soup.find_all("form")

    def form_details(self, form):
        details_of_form = {}
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get")
        inputs = []

        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({
                "type": input_type,
                "name": input_name,
                "value": input_value,
            })

        details_of_form['action'] = action
        details_of_form['method'] = method
        details_of_form['inputs'] = inputs
        return details_of_form

    def vulnerable(self, response):
        errors = {
            "you have an error in your SQL syntax",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
        }
        for error in errors:
            if error in response.content.decode().lower():
                return True
        return False

    def sql_injection_scan(self):
        self.clear_results()

        url = self.url_entry.get()

        forms = self.get_forms(url)
        self.results_text.insert(tk.END, f"Scanning URL: {url}\n\n")

        for form in forms:
            form_details = self.form_details(form)
            method = form_details['method']
            action = urljoin(url, form_details['action'])
            inputs = form_details['inputs']
            data = {}

            for input_data in inputs:
                if input_data['type'] == "text" or input_data['type'] == "search":
                    input_data['value'] = "' OR '1'='1"

                input_name = input_data['name']
                input_value = input_data['value']
                data[input_name] = input_value

            if method == "post":
                response = requests.post(action, data=data)
            else:
                response = requests.get(action, params=data)

            if self.vulnerable(response):
                self.results_text.insert(tk.END, f"Vulnerable form found in: {action}\n")
                self.results_text.insert(tk.END, f"Response Content: {response.content.decode()}\n\n")
            else:
               self.results_text.insert(tk.END, "No SQL Injection Vulnerability Detected\n")
            break    

        self.results_text.insert(tk.END, "Scan complete.")

def main():
    root = tk.Tk()
    root.title("Security Utility")
    root.geometry("900x500")

    # Create a style object for the tab headings
    style = ttk.Style(root)
    style.configure("TNotebook.Tab", font=("Arial", 14, "bold"), anchor="center")

    tab_control = ttk.Notebook(root)

    # Create tab frames
    home_tab = ttk.Frame(tab_control)
    password_generator_tab = ttk.Frame(tab_control)
    cipher_cryptographic_machine_tab = ttk.Frame(tab_control)
    port_scanner_tab = ttk.Frame(tab_control)
    sql_injection_scanner_tab = ttk.Frame(tab_control)

    # Add tabs to the tab control
    tab_control.add(home_tab, text="Home")
    tab_control.add(password_generator_tab, text="Password Generator")
    tab_control.add(cipher_cryptographic_machine_tab, text="Cipher Cryptographic Machine")
    tab_control.add(port_scanner_tab, text="Port Scanner")
    tab_control.add(sql_injection_scanner_tab, text="SQL Injection Scanner")

    # Create instances of the tab classes
    Home(home_tab)
    PasswordGenerator(password_generator_tab)
    CipherCryptographicMachine(cipher_cryptographic_machine_tab)
    PortScanner(port_scanner_tab)
    SQLInjectionScanner(sql_injection_scanner_tab)

    tab_control.pack(expand=1, fill="both")

    root.mainloop()

if __name__ == "__main__":
    main()
