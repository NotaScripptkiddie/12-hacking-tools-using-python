import socket
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
import threading
import time
import re
from datetime import datetime

class PortScanner:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Advanced Python Port Scanner")
        self.root.geometry("600x700")
        self.root.resizable(True, True)
        
        # Variables for scan control
        self.scanning = False
        self.scan_thread = None
        
        # Common ports dictionary for service identification
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 587: "SMTP", 465: "SMTPS", 3389: "RDP", 5432: "PostgreSQL",
            3306: "MySQL", 1433: "MSSQL", 6379: "Redis", 27017: "MongoDB"
        }
        
        self.setup_gui()
        
    def setup_gui(self):
        """Create and configure the GUI elements"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights for responsiveness
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Advanced Port Scanner", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Target IP/Hostname input
        ttk.Label(main_frame, text="Target IP/Hostname:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_target = ttk.Entry(main_frame, width=30)
        self.entry_target.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        self.entry_target.insert(0, "127.0.0.1")  # Default localhost
        
        # Port range inputs
        ttk.Label(main_frame, text="Start Port:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.entry_start = ttk.Entry(main_frame, width=15)
        self.entry_start.grid(row=2, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        self.entry_start.insert(0, "1")  # Default start port
        
        ttk.Label(main_frame, text="End Port:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.entry_end = ttk.Entry(main_frame, width=15)
        self.entry_end.grid(row=3, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        self.entry_end.insert(0, "1000")  # Default end port
        
        # Timeout setting
        ttk.Label(main_frame, text="Timeout (seconds):").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.entry_timeout = ttk.Entry(main_frame, width=15)
        self.entry_timeout.grid(row=4, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        self.entry_timeout.insert(0, "1")  # Default timeout
        
        # Quick scan presets
        presets_frame = ttk.LabelFrame(main_frame, text="Quick Scan Presets", padding="5")
        presets_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Button(presets_frame, text="Common Ports (1-1000)", 
                  command=lambda: self.set_preset(1, 1000)).grid(row=0, column=0, padx=5)
        ttk.Button(presets_frame, text="Well-known (1-1024)", 
                  command=lambda: self.set_preset(1, 1024)).grid(row=0, column=1, padx=5)
        ttk.Button(presets_frame, text="All Ports (1-65535)", 
                  command=lambda: self.set_preset(1, 65535)).grid(row=0, column=2, padx=5)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=3, pady=20)
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5)
        
        ttk.Button(button_frame, text="Clear Results", command=self.clear_results).grid(row=0, column=2, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='determinate')
        self.progress.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        # Status label
        self.status_label = ttk.Label(main_frame, text="Ready to scan", foreground="green")
        self.status_label.grid(row=8, column=0, columnspan=3, pady=5)
        
        # Results area
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="5")
        results_frame.grid(row=9, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(9, weight=1)
        
        # Results text area with scrollbar
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, width=70)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
    def set_preset(self, start, end):
        """Set predefined port ranges for quick scanning"""
        self.entry_start.delete(0, tk.END)
        self.entry_start.insert(0, str(start))
        self.entry_end.delete(0, tk.END)
        self.entry_end.insert(0, str(end))
        
    def validate_inputs(self):
        """Validate user inputs before starting scan"""
        target = self.entry_target.get().strip()
        
        # Validate target (IP address or hostname)
        if not target:
            raise ValueError("Target IP/hostname cannot be empty")
        
        # Basic IP address validation
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, target):
            # Validate IP octets
            octets = target.split('.')
            for octet in octets:
                if not (0 <= int(octet) <= 255):
                    raise ValueError("Invalid IP address format")
        
        # Validate port range
        try:
            start_port = int(self.entry_start.get())
            end_port = int(self.entry_end.get())
            timeout = float(self.entry_timeout.get())
        except ValueError:
            raise ValueError("Port numbers and timeout must be numeric")
        
        if not (1 <= start_port <= 65535):
            raise ValueError("Start port must be between 1 and 65535")
        if not (1 <= end_port <= 65535):
            raise ValueError("End port must be between 1 and 65535")
        if start_port > end_port:
            raise ValueError("Start port cannot be greater than end port")
        if end_port - start_port > 65534:
            raise ValueError("Port range too large")
        if timeout <= 0 or timeout > 30:
            raise ValueError("Timeout must be between 0.1 and 30 seconds")
            
        return target, start_port, end_port, timeout
    
    def resolve_hostname(self, target):
        """Resolve hostname to IP address"""
        try:
            ip = socket.gethostbyname(target)
            return ip
        except socket.gaierror:
            raise ValueError(f"Cannot resolve hostname: {target}")
    
    def scan_port(self, target_ip, port, timeout):
        """Scan a single port and return result"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def get_service_name(self, port):
        """Get service name for a given port"""
        return self.common_ports.get(port, "Unknown")
    
    def scan_ports_thread(self, target, start_port, end_port, timeout):
        """Main scanning function that runs in a separate thread"""
        try:
            # Resolve hostname if necessary
            original_target = target
            target_ip = self.resolve_hostname(target)
            
            # Update status
            self.root.after(0, lambda: self.status_label.config(
                text=f"Scanning {original_target} ({target_ip})...", foreground="blue"))
            
            # Initialize progress
            total_ports = end_port - start_port + 1
            self.root.after(0, lambda: self.progress.config(maximum=total_ports, value=0))
            
            # Clear previous results
            self.root.after(0, self.clear_results)
            
            # Add scan header
            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            header = f"=== Port Scan Results ===\n"
            header += f"Target: {original_target} ({target_ip})\n"
            header += f"Port Range: {start_port}-{end_port}\n"
            header += f"Scan Time: {scan_time}\n"
            header += f"Timeout: {timeout}s\n"
            header += "=" * 50 + "\n\n"
            
            self.root.after(0, lambda: self.results_text.insert(tk.END, header))
            
            open_ports = []
            scanned_ports = 0
            
            # Scan each port
            for port in range(start_port, end_port + 1):
                if not self.scanning:  # Check if scan was stopped
                    break
                
                is_open = self.scan_port(target_ip, port, timeout)
                
                if is_open:
                    open_ports.append(port)
                    service = self.get_service_name(port)
                    result_line = f"Port {port}: OPEN - {service}\n"
                    self.root.after(0, lambda line=result_line: self.results_text.insert(tk.END, line))
                    self.root.after(0, lambda: self.results_text.see(tk.END))
                
                scanned_ports += 1
                
                # Update progress
                self.root.after(0, lambda: self.progress.config(value=scanned_ports))
                
                # Update status every 10 ports
                if scanned_ports % 10 == 0:
                    self.root.after(0, lambda p=port: self.status_label.config(
                        text=f"Scanning port {p}... ({len(open_ports)} open ports found)"))
            
            # Scan completed
            if self.scanning:  # Only show completion if not stopped manually
                summary = f"\n" + "=" * 50 + "\n"
                summary += f"Scan completed!\n"
                summary += f"Total ports scanned: {scanned_ports}\n"
                summary += f"Open ports found: {len(open_ports)}\n"
                
                if open_ports:
                    summary += f"Open ports: {', '.join(map(str, open_ports))}\n"
                else:
                    summary += "No open ports found.\n"
                
                self.root.after(0, lambda: self.results_text.insert(tk.END, summary))
                self.root.after(0, lambda: self.status_label.config(
                    text=f"Scan completed! Found {len(open_ports)} open ports", foreground="green"))
            else:
                self.root.after(0, lambda: self.status_label.config(
                    text="Scan stopped by user", foreground="orange"))
                
        except Exception as e:
            error_msg = f"Scan error: {str(e)}"
            self.root.after(0, lambda: self.status_label.config(text=error_msg, foreground="red"))
            self.root.after(0, lambda: messagebox.showerror("Scan Error", error_msg))
        finally:
            # Re-enable scan button and disable stop button
            self.root.after(0, lambda: self.scan_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED))
            self.scanning = False
    
    def start_scan(self):
        """Start the port scanning process"""
        try:
            # Validate inputs
            target, start_port, end_port, timeout = self.validate_inputs()
            
            # Check if already scanning
            if self.scanning:
                messagebox.showwarning("Scan in Progress", "A scan is already running!")
                return
            
            # Confirm large port range scans
            port_count = end_port - start_port + 1
            if port_count > 10000:
                result = messagebox.askyesno("Large Scan Warning", 
                    f"You are about to scan {port_count} ports. This may take a long time. Continue?")
                if not result:
                    return
            
            # Set scanning state
            self.scanning = True
            self.scan_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            
            # Start scanning in a separate thread
            self.scan_thread = threading.Thread(
                target=self.scan_ports_thread, 
                args=(target, start_port, end_port, timeout),
                daemon=True
            )
            self.scan_thread.start()
            
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {str(e)}")
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.scanning:
            self.scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.status_label.config(text="Stopping scan...", foreground="orange")
    
    def clear_results(self):
        """Clear the results text area"""
        self.results_text.delete(1.0, tk.END)
    
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()

# Create and run the application
if __name__ == "__main__":
    app = PortScanner()
    app.run()