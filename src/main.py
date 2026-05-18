import atexit
import socket
import sys
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


def _pause_on_exit():
    """Keep the console open when launched from Explorer/double-click."""
    try:
        import msvcrt
        print("\nPress any key to exit...")
        msvcrt.getch()
    except ImportError:
        input("\nPress Enter to exit...")

_PROGRESS_LOCK = threading.Lock()
_PROGRESS_WIDTH = 30
# Width used to pad/erase the progress line. Sized to comfortably hold
# bar + counters + IP:port label.
_PROGRESS_LINE_WIDTH = 110


def render_progress(done, total, current_label):
    """Draw an in-place progress bar with the latest target being scanned."""
    pct = (done / total) if total else 1.0
    filled = int(_PROGRESS_WIDTH * pct)
    bar = '█' * filled + '░' * (_PROGRESS_WIDTH - filled)
    line = f"\r[{bar}] {done}/{total} ({pct * 100:5.1f}%) | scanning: {current_label}"
    sys.stdout.write(line.ljust(_PROGRESS_LINE_WIDTH))
    sys.stdout.flush()


def clear_progress_line():
    """Wipe the current progress line so a regular print can follow cleanly."""
    sys.stdout.write('\r' + ' ' * _PROGRESS_LINE_WIDTH + '\r')
    sys.stdout.flush()

def check_port(target_ip, target_port, timeout=3, verbose=True) -> bool:
    """
    Tests if a specific TCP port is open on a target IP address.

    Args:
        target_ip (str): The IP address to check (e.g., '192.168.1.1').
        target_port (int): The port number to test.
        timeout (int): The connection timeout in seconds.
        verbose (bool): Whether to print detailed output.

    Returns:
        bool: True if the port is open/reachable, False otherwise.
    """
    try:
        # Create a TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        if verbose:
            print(f"Attempting to connect to {target_ip} on port {target_port}...")

        # Attempt to connect
        s.connect((target_ip, target_port))

        # If connect succeeds, the port is open
        if verbose:
            print(f"SUCCESS: Port {target_port} on {target_ip} is OPEN.")
        s.close()
        return True

    except socket.timeout:
        if verbose:
            print(f"FAILURE: Connection to {target_ip}:{target_port} timed out.")
        return False
    except ConnectionRefusedError:
        if verbose:
            print(f"FAILURE: Connection to {target_ip}:{target_port} was refused (Port is likely closed or filtered).")
        return False
    except socket.gaierror:
        if verbose:
            print(f"ERROR: Address resolution error. Check if the IP address '{target_ip}' is valid.")
        return False
    except Exception as e:
        if verbose:
            print(f"An unexpected error occurred: {e}")
        return False

def parse_ip_range(ip_input):
    """
    Parse IP input and return a list of IP addresses to scan.
    
    Supports:
    - Single IP: 192.168.1.1
    - CIDR notation: 192.168.1.0/24
    - Range notation: 192.168.1.1-192.168.1.10
    
    Args:
        ip_input (str): The IP address or range input.
        
    Returns:
        list: List of IP addresses as strings.
    """
    ip_list = []
    
    try:
        # Check if it's CIDR notation (contains '/')
        if '/' in ip_input:
            network = ipaddress.IPv4Network(ip_input, strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
            if not ip_list:  # Handle /32 networks
                ip_list = [str(network.network_address)]
        
        # Check if it's range notation (contains '-')
        elif '-' in ip_input:
            start_ip, end_ip = ip_input.split('-', 1)
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            
            # Convert to IP addresses
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            
            # Generate range
            current = start
            while current <= end:
                ip_list.append(str(current))
                current += 1
        
        # Single IP address
        else:
            # Validate it's a proper IP
            ipaddress.IPv4Address(ip_input)
            ip_list = [ip_input]
            
    except Exception as e:
        raise ValueError(f"Invalid IP address or range format: {e}")
    
    return ip_list

def parse_port_range(port_input):
    """
    Parse port input and return a sorted list of unique ports to scan.

    Supports:
    - Single port: 80
    - Range notation: 1-1024
    - Comma-separated list / mix: 22,80,443,8000-8010
    """
    ports = set()

    for token in port_input.split(','):
        token = token.strip()
        if not token:
            continue

        if '-' in token:
            start_str, end_str = token.split('-', 1)
            start = int(start_str.strip())
            end = int(end_str.strip())
            if start > end:
                start, end = end, start
            if not (0 < start < 65536) or not (0 < end < 65536):
                raise ValueError(f"Port range '{token}' out of bounds (1-65535).")
            ports.update(range(start, end + 1))
        else:
            port = int(token)
            if not (0 < port < 65536):
                raise ValueError(f"Port '{token}' out of bounds (1-65535).")
            ports.add(port)

    if not ports:
        raise ValueError("No valid ports provided.")

    return sorted(ports)

def scan_ip_port(ip, port, timeout):
    """
    Scan a single IP and port combination.
    Used for threading.
    """
    result = check_port(ip, port, timeout, verbose=False)
    return ip, port, result

if __name__ == "__main__":
    atexit.register(_pause_on_exit)
    print("--- Port Checker ---")
    print("IP formats: single (192.168.1.1), CIDR (192.168.1.0/24), or range (192.168.1.1-192.168.1.10)")
    print("Port formats: single (80), range (1-1024), or list (22,80,443,8000-8010)")
    print()

    # Get input from the user
    ip_input = input("Enter IP address or range: ").strip()
    port_input = input("Enter port(s) to test (e.g., 80 or 1-1024): ").strip()

    # Validate inputs
    if not ip_input:
        print("Error: IP address cannot be empty.")
        sys.exit(1)

    if not port_input:
        print("Error: Port cannot be empty.")
        sys.exit(1)

    # Parse IP range
    try:
        ip_list = parse_ip_range(ip_input)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Parse port range
    try:
        port_list = parse_port_range(port_input)
    except ValueError as e:
        print(f"Error: Invalid port input - {e}")
        sys.exit(1)

    CONNECTION_TIMEOUT = 3
    open_results = []   # list of (ip, port)
    closed_count = 0
    total_checks = len(ip_list) * len(port_list)

    print(f"\nScanning {len(ip_list)} IP(s) across {len(port_list)} port(s) - {total_checks} total checks...")
    print("-" * 50)

    # Use detailed output only when there's exactly one IP and one port
    if total_checks == 1:
        ip = ip_list[0]
        port = port_list[0]
        if check_port(ip, port, CONNECTION_TIMEOUT, verbose=True):
            open_results.append((ip, port))
        else:
            closed_count += 1
    else:
        print("Using multi-threaded scanning for faster results...\n")

        done = 0
        render_progress(0, total_checks, "starting...")

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [
                executor.submit(scan_ip_port, ip, port, CONNECTION_TIMEOUT)
                for ip in ip_list
                for port in port_list
            ]

            for future in as_completed(futures):
                ip, port, result = future.result()
                with _PROGRESS_LOCK:
                    done += 1
                    if result:
                        open_results.append((ip, port))
                        clear_progress_line()
                        print(f"✓ OPEN  {ip}:{port}")
                    else:
                        closed_count += 1
                    render_progress(done, total_checks, f"{ip}:{port}")

        # Move off the progress line after scanning finishes.
        sys.stdout.write('\n')
        sys.stdout.flush()

    # Summary
    print("\n" + "=" * 50)
    print("--- SCAN SUMMARY ---")
    print(f"IPs scanned:           {len(ip_list)}")
    print(f"Ports per IP:          {len(port_list)}")
    print(f"Total checks:          {total_checks}")
    print(f"Open ports found:      {len(open_results)}")
    print(f"Closed/Filtered:       {closed_count}")

    if open_results:
        print("\n🟢 OPEN ports:")
        # Group by IP for cleaner output
        by_ip = {}
        for ip, port in open_results:
            by_ip.setdefault(ip, []).append(port)
        for ip in sorted(by_ip, key=lambda x: ipaddress.IPv4Address(x)):
            ports_str = ", ".join(str(p) for p in sorted(by_ip[ip]))
            print(f"  - {ip}: {ports_str}")
