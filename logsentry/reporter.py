import csv


def export_to_csv(data: list,filename: str)->None:
    """
        Exports a list of dictionaries containing IP data to a CSV file.

        Args:
            data (list): List of dictionaries with 'ip' and 'malicious_engines' keys.
            filename (str): The output CSV filename.
        """

    with open(filename, mode="w", newline="") as archivo:

        writer = csv.DictWriter(archivo, fieldnames=["ip", "malicious_engines"])
        writer.writeheader()
        writer.writerows(data)