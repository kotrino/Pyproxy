import pydivert

def list_interfaces():
    interfaces = pydivert.WinDivert.get_interfaces()
    for iface in interfaces:
        print(f"Index: {iface.index}, Name: {iface.name}, Description: {iface.description}")

list_interfaces()