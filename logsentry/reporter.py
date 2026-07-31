import csv


def export_to_csv(data: list,filename: str)->None:

    with open(filename, mode="w", newline="") as archivo:

        writer = csv.DictWriter(archivo, fieldnames=["ip", "malicious_engines"])
        writer.writeheader()
        writer.writerows(data)