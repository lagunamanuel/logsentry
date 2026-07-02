import re

def extract_ips_from_log(log_path: str, threshold: int = 5) -> list:
    """
    Reads a text log file and extracts valid IPv4 addresses.
    """
    extracted_ips = []

    ip_counts = {}
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'



    try:
        with open(log_path, 'r') as file:
            lines = file.readlines()
            
            for line in lines:
                matches = re.findall(ipv4_pattern, line)
                if matches:
                    for match in matches:
                        if match in ip_counts:
                            ip_counts[match] += 1
                        else:
                            ip_counts[match] = 1

        for i in ip_counts:
            if ip_counts[i] >= threshold:
                extracted_ips.append(i)

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_path}")
        
    return extracted_ips