import pyshark

# Replace with the correct interface from your list
interface = r"\Device\NPF_{2BA22351-5BA9-4A5B-8F00-8CDE427DFFD8}"  # Update this based on your network

print(f"Capturing packets on: {interface}")

capture = pyshark.LiveCapture(interface=interface)

for packet in capture.sniff_continuously(packet_count=100):
    print(packet)
