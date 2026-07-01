import requests
import os

def check_ip_virustotal(ip_address: str) -> dict:
    """
    Queries the VirusTotal v3 API for information about a specific IP address.
    """
    api_key = os.environ.get("VT_API_KEY")
    result_data = {}
    
    if not api_key:
        print("Error: VT_API_KEY environment variable is not set.")
    else:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result_data = response.json()
        else:
            print(f"API Request failed with status code {response.status_code}")
            
    return result_data