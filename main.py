import tkinter as tk
import subprocess
import ipaddress
import platform

def block_iptables():
    ip_address = ip_entry.get("1.0", "end-1c").strip()

    # Validate the IP address
    if not validate_ip_address(ip_address):
        output_text1.insert(tk.END, "Invalid IP address\n")
        return

    # Check if IP address is already blocked
    if is_ip_blocked_iptables(ip_address):
        output_text1.insert(tk.END, "Already blocked via iptables\n")
        return

    try:
        # Execute the iptables command to block packets to the IP address
        subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip_address, '-j', 'DROP'])
        output_text2.insert(tk.END, f"{ip_address}\n")
        output_text1.insert(tk.END, f"Blocked packets to IP: {ip_address} via iptables\n")
    except subprocess.CalledProcessError:
        output_text1.insert(tk.END, "Failed to block packets to IP address via iptables\n")

def block_iptables_hosts():
    ip_address = ip_entry.get("1.0", "end-1c").strip()

    # Validate the IP address
    if not validate_ip_address(ip_address):
        output_text1.insert(tk.END, "Invalid IP address\n")
        return

    # Check if IP address is already blocked
    if is_ip_blocked_iptables(ip_address) and is_ip_blocked_hosts(ip_address):
        output_text1.insert(tk.END, "Already blocked via iptables and hosts file\n")
        return

    try:
        # Execute the iptables command to block packets to the IP address
        subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip_address, '-j', 'DROP'])
        
        # Add the IP address entry to the hosts file
        with open(get_hosts_file(), "a") as hosts_file:
            hosts_file.write(f"\n# Blocked IP\n{ip_address}  localhost\n")

        output_text2.insert(tk.END, f"{ip_address}\n")
        output_text1.insert(tk.END, f"Blocked packets to IP: {ip_address} via iptables and hosts file\n")
    except subprocess.CalledProcessError:
        output_text1.insert(tk.END, "Failed to block packets to IP address via iptables and hosts file\n")
    except IOError:
        output_text1.insert(tk.END, "Failed to block packets to IP address via hosts file\n")

def unblock_ip():
    ip_address = ip_entry.get("1.0", "end-1c").strip()

    # Validate the IP address
    if not validate_ip_address(ip_address):
        output_text1.insert(tk.END, "Invalid IP address\n")
        return

    # Check if IP address is blocked
    if not is_ip_blocked_iptables(ip_address) and not is_ip_blocked_hosts(ip_address):
        output_text1.insert(tk.END, "The given IP is not blocked\n")
        return

    try:
        # Execute the iptables command to remove the rule blocking packets to the IP address
        subprocess.run(['sudo', 'iptables', '-D', 'OUTPUT', '-d', ip_address, '-j', 'DROP'])
        
        # Read the hosts file and remove the IP address entry
        with open(get_hosts_file(), "r") as hosts_file:
            lines = hosts_file.readlines()

        with open(get_hosts_file(), "w") as hosts_file:
            for line in lines:
                if ip_address not in line:
                    hosts_file.write(line)

        output_text2.delete(f"1.0", tk.END)  # Remove all content from Output Text Box 2
        blocked_ips_iptables = get_blocked_ips_iptables()
        for ip in blocked_ips_iptables:
            output_text2.insert(tk.END, f"{ip}\n")

        output_text1.insert(tk.END, f"Unblocked packets to IP: {ip_address} from iptables and hosts file\n")
    except subprocess.CalledProcessError:
        output_text1.insert(tk.END, "Failed to unblock packets to IP address from iptables and hosts file\n")
    except IOError:
        output_text1.insert(tk.END, "Failed to unblock packets to IP address from hosts file\n")

def validate_ip_address(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def is_ip_blocked_iptables(ip_address):
    try:
        output = subprocess.check_output(['sudo', 'iptables', '-L', 'OUTPUT', '-n', '-v'])
        output = output.decode('utf-8')
        return ip_address in output
    except subprocess.CalledProcessError:
        return False

def is_ip_blocked_hosts(ip_address):
    with open(get_hosts_file(), "r") as hosts_file:
        lines = hosts_file.readlines()
        return any(ip_address in line for line in lines)

def get_blocked_ips_iptables():
    try:
        output = subprocess.check_output(['sudo', 'iptables', '-L', 'OUTPUT', '-n', '-v'])
        output = output.decode('utf-8')
        blocked_ips = []
        for line in output.split('\n'):
            if line.startswith('DROP'):
                parts = line.split()
                if len(parts) > 3:
                    blocked_ips.append(parts[3])
        return blocked_ips
    except subprocess.CalledProcessError:
        return []

def get_hosts_file():
    system = platform.system()
    if system == "Windows":
        return r"C:\Windows\System32\drivers\etc\hosts"
    elif system == "Linux":
        return "/etc/hosts"
    elif system == "Darwin":  # macOS
        return "/private/etc/hosts"
    else:
        raise NotImplementedError(f"Unsupported system: {system}")

# Create the main window
window = tk.Tk()
window.title("IP Blocker")
window.geometry("800x600")

# IP Address Label
ip_label = tk.Label(window, text="Enter IP Address:", font=("Arial", 14))
ip_label.place(relx=0.5, rely=0.1, anchor=tk.CENTER)

# IP Address Entry
ip_entry = tk.Text(window, height=1, width=20, font=("Arial", 14))
ip_entry.place(relx=0.5, rely=0.2, anchor=tk.CENTER)


# Block via iptables Button
block_iptables_button = tk.Button(window, text="Block via iptables", font=("Arial", 12), command=block_iptables)
block_iptables_button.place(relx=0.2, rely=0.3, anchor=tk.CENTER)

# Block via iptables and hosts Button
block_iptables_hosts_button = tk.Button(window, text="Block via iptables and hosts", font=("Arial", 12), command=block_iptables_hosts)
block_iptables_hosts_button.place(relx=0.5, rely=0.3, anchor=tk.CENTER)

# Unblock Button
unblock_button = tk.Button(window, text="Unblock IP", font=("Arial", 12), command=unblock_ip)
unblock_button.place(relx=0.8, rely=0.3, anchor=tk.CENTER)

# Output Text Box 1 (Log Box)
output_text1 = tk.Text(window, height=10, width=30, font=("Arial", 12), bg="white")
output_text1.place(relx=0.3, rely=0.6, anchor=tk.CENTER)

# Output Text Box 2 (Blocked IPs)
output_text2 = tk.Text(window, height=10, width=30, font=("Arial", 12), bg="white")
output_text2.place(relx=0.7, rely=0.6, anchor=tk.CENTER)

# Initialize Output Text Box 2 with currently blocked IPs
blocked_ips_iptables = get_blocked_ips_iptables()
for ip in blocked_ips_iptables:
    output_text2.insert(tk.END, f"{ip}\n")

# Start the GUI event loop
window.mainloop()

