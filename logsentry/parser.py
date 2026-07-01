import re

def extract_ips_from_log(log_path: str) -> list:
    """
    Reads a text log file and extracts valid IPv4 addresses.
    """
    extracted_ips = []
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    
    try:
        with open(log_path, 'r') as file:
            lines = file.readlines()
            
            for line in lines:
                matches = re.findall(ipv4_pattern, line)
                if matches:
                    extracted_ips.extend(matches)
                    
    except FileNotFoundError:
        print(f"Error: Log file not found at {log_path}")
        
    return extracted_ips