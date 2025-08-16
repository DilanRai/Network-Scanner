# network_scanner.py

from scapy.all import ARP, Ether, srp

def scan_network(target_ip):
    """
    Scans the network for active devices.
    
    :param target_ip: Target IP range (example: "192.168.1.1/24")
    :return: List of devices found on the network
    """

    # Create ARP request packet
    arp = ARP(pdst=target_ip)

    # Create Ethernet frame
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine Ethernet + ARP request
    packet = ether/arp

    # Send the packet and capture the response
    result = srp(packet, timeout=2, verbose=0)[0]

    # Store devices
    devices = []
    for sent, received in result:
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc
        })

    return devices


def display_result(devices):
    print("Available Devices in the Network:")
    print("IP Address" + " " * 18 + "MAC Address")
    print("-" * 50)
    for device in devices:
        print("{:20}    {}".format(device['ip'], device['mac']))


if __name__ == "__main__":
    target = "192.168.1.1/24"  # Change this to your network subnet
    scanned_devices = scan_network(target)
    display_result(scanned_devices)
# This script scans the network for active devices and displays their IP and MAC addresses.
# Ensure you run this script with appropriate permissions (e.g., as root or administrator) to access network interfaces.