# Packets are sniffed here and passed to the AI for further processing
from scapy.all import Ether, PcapReader, Raw, sniff, wrpcap
from rich.console import Console
    
console = Console()


# Packet sniffing and saving to a file for further AI processing.
def packet_sniffer(iface):
    console.print("[bold yellow]Starting packet sniffing...[/bold yellow]")                     
    while True:
        pkts = sniff(iface=iface, count=10, timeout=10)
        if not pkts:
            break
        wrpcap("capture.pcap", pkts)
        console.print(f"[bold green]Captured {len(pkts)} packets.[/bold green]")


# Read the PCAP file and pass the packets to the AI for analysis

def read_pcap_file():
    filepath="capture.pcap"
    max_packets = 10
    packet_context = []
    with PcapReader(filepath) as pcap_iter:
        for i, pkt in enumerate(pcap_iter):
            if i >= max_packets:
                break
            
            # Extract lightweight dictionary fields an LLM can easily digest
            pkt_info = {
                "summary": pkt.summary(),
                "layers": [layer.__name__ for layer in pkt.layers()],
                "data": bytes(pkt).hex()
            }
            packet_context.append(pkt_info)
    return packet_context


def parse_packet_data(pkt_info: dict) -> dict:
    """Reconstructs the Scapy object from hex bytes and extracts human-readable text."""
    # Convert the hex string back to raw bytes
    raw_bytes = bytes.fromhex(pkt_info["data"])
    
    # Dissect bytes back into a hierarchical Scapy object 
    dissected_pkt = Ether(raw_bytes)
    
    # Extract application-layer clear text if present
    readable_payload = ""
    if dissected_pkt.haslayer(Raw):
        try:
            readable_payload = dissected_pkt[Raw].load.decode('utf-8', errors='ignore')
        except Exception:
            readable_payload = "<binary payload>"

    ready_to_feed_data ={
        "summary": pkt_info["summary"],
        "layers": pkt_info["layers"],
        "readable_text": readable_payload
    }
    return ready_to_feed_data