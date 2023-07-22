import tkinter as tk
from tkinter import ttk

# Create the main window
root = tk.Tk()
root.geometry("600x600")
root.title("Security Utility")
root.iconbitmap("securitysymbol.ico")


# Create the notebook
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

# Create the four tabs
tab1 = ttk.Frame(notebook)
tab2 = ttk.Frame(notebook)
tab3 = ttk.Frame(notebook)
tab4 = ttk.Frame(notebook)
tab5 = ttk.Frame(notebook)

notebook.add(tab1, text="Home")
notebook.add(tab2, text="Port Scanner")
notebook.add(tab3, text="SQL Injection Vulnerability Scanner")
notebook.add(tab4, text="Cipher Cryptography Machine")
notebook.add(tab5, text="Password Generator")

# Add content to the tabs
ttk.Label(tab1, text="Welcome").pack(pady=30)
ttk.Label(tab2, text="Port Scanner").pack(pady=10)
ttk.Label(tab3, text="SQL Injection Vulnerability Scanner").pack(pady=10)
ttk.Label(tab4, text="Cipher Cryptography Machine").pack(pady=10)
ttk.Label(tab5, text="Password Generator").pack(pady=10)

# Start the GUI
root.mainloop()
