import os

import requests


VT_TIMEOUT = (5, 20)


def check_ip_virustotal(ip_address: str) -> dict:
    """
    Queries VirusTotal for information about an IP address.

    Args:
        ip_address (str): The IP address to query.

    Returns:
        dict: The response payload, or an empty dict when the request
            fails or the response is not a JSON object.

    Raises:
        EnvironmentError: If VT_API_KEY is not set.
    """
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        raise EnvironmentError("VT_API_KEY environment variable is not set.")

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    try:
        response = requests.get(url, headers=headers, timeout=VT_TIMEOUT)

        if response.status_code != 200:
            print(
                f"[!] Error: VirusTotal request for {ip_address} "
                f"failed with status code {response.status_code}"
            )
            return {}

        result_data = response.json()

    except requests.exceptions.RequestException as exc:
        print(f"[!] Error: VirusTotal request failed for {ip_address}: {exc}")
        return {}

    if not isinstance(result_data, dict):
        print(f"[!] Error: Invalid VirusTotal response for {ip_address}")
        return {}

    return result_data