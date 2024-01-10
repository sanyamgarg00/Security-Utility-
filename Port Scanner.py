from tkinter import *
from socket import *
import threading

class PortScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner")

        # Configure window size and background color
        self.root.geometry("414x600")
        self.root.configure(bg="light grey")

        # Add label on top
        self.top_label = Label(self.root, text="PORT SCANNER", font=("Arial Bold", 20))
        self.top_label.grid(row=0, column=0, columnspan=2, pady=20, padx=5)

        # Create input fields
        self.ip_label = Label(self.root, text="Enter IP address:", font=("Arial Bold", 10))
        self.ip_label.grid(row=1, column=0, pady=5, padx=5, sticky=W)
        self.ip_label.configure(bg="light grey")
        self.ip_entry = Entry(self.root)
        self.ip_entry.grid(row=1, column=1, pady=5, padx=5, sticky=W)

        self.ports_label = Label(self.root, text="Enter port range:", font=("Arial Bold", 10))
        self.ports_label.grid(row=2, column=0, pady=5, padx=5, sticky=W)
        self.ports_label.configure(bg="light grey")
        self.ports_entry = Entry(self.root)
        self.ports_entry.grid(row=2, column=1, pady=5, padx=5, sticky=W)

        # Create buttons
        self.scan_button = Button(self.root, text="Scan Ports", command=self.scan_ports, font=("Arial Bold", 10))
        self.scan_button.grid(row=3, column=0, pady=10, padx=5, sticky=W)

        self.clear_button = Button(self.root, text="Clear Results", command=self.clear_results, font=("Arial Bold", 10))
        self.clear_button.grid(row=3, column=1, pady=10, padx=5, sticky=W)

        # Create output field
        self.results_label = Label(self.root, text="Results:", font=("Arial Bold", 11))
        self.results_label.configure(bg="light grey")
        self.results_label.grid(row=4, column=0, pady=5, padx=5, sticky=W)

        self.results_text = Text(self.root, width=50, height=20)
        self.results_text.grid(row=5, column=0, columnspan=2, pady=5, padx=5)


    def clear_results(self):
        self.results_text.delete('1.0', END)

    def scan_ports(self):
        self.clear_results()

        target = self.ip_entry.get()
        port_range = self.ports_entry.get().split("-")

        if len(port_range) != 2:
            self.results_text.insert(END, "Invalid port range.")
            return

        try:
            start_port = int(port_range[0])
            end_port = int(port_range[1])
        except ValueError:
            self.results_text.insert(END, "Invalid port range.")
            return

        self.results_text.insert(END, "Scanning ports %d-%d...\n" % (start_port, end_port))

        # Use threading to avoid GUI freezing
        t = threading.Thread(target=self.do_scan, args=(target, start_port, end_port))
        t.start()

    def do_scan(self, target, start_port, end_port):
        # Scan each port in the specified range
        for port in range(start_port, end_port+1):
            s = socket(AF_INET, SOCK_STREAM)
            s.settimeout(1)

            try:
                conn = s.connect_ex((target, port))
                if conn == 0:
                    self.results_text.insert(END, "Port %d: OPEN\n" % port)
                    s.close()
            except:
                pass

        self.results_text.insert(END, "Scan complete.")
       
if __name__ == "__main__":
    root = Tk()
    scanner = PortScanner(root)
    root.mainloop()