from scapy.all import *
from datetime import datetime

tcp = 0
udp = 0
icmp = 0
other = 0
total = 0

print("="*75)
print("        MINI NETWORK PACKET ANALYZER")
print("="*75)
print("Capturing 20 packets...\n")

def analyze(pkt):

    global tcp, udp, icmp, other, total

    total += 1

    print("="*75)
    print("Packet Number :", total)
    print("Time          :", datetime.now().strftime("%H:%M:%S"))

    if IP in pkt:

        print("Source IP     :", pkt[IP].src)
        print("Destination IP:", pkt[IP].dst)
        print("Packet Size   :", len(pkt), "Bytes")

        if TCP in pkt:
            tcp += 1
            print("Protocol      : TCP")
            print("Source Port   :", pkt[TCP].sport)
            print("Dest Port     :", pkt[TCP].dport)

        elif UDP in pkt:
            udp += 1
            print("Protocol      : UDP")
            print("Source Port   :", pkt[UDP].sport)
            print("Dest Port     :", pkt[UDP].dport)

        elif ICMP in pkt:
            icmp += 1
            print("Protocol      : ICMP")

        else:
            other += 1
            print("Protocol      : Other")

        if Raw in pkt:
            try:
                data = pkt[Raw].load.decode(errors="ignore")
                print("Payload       :", data[:80])
            except:
                print("Payload       : Binary Data")

        else:
            print("Payload       : No Payload")

sniff(prn=analyze, count=20)

print("\n")
print("="*75)
print("NETWORK TRAFFIC SUMMARY")
print("="*75)

print("Total Packets :", total)
print("TCP Packets   :", tcp)
print("UDP Packets   :", udp)
print("ICMP Packets  :", icmp)
print("Other Packets :", other)

print("\nTraffic Analysis")

if tcp > udp and tcp > icmp:
    print("Most traffic was TCP (Web browsing, HTTPS, etc.)")

elif udp > tcp and udp > icmp:
    print("Most traffic was UDP (DNS, Streaming, etc.)")

elif icmp > 0:
    print("ICMP packets detected (Ping/Network Diagnostics)")

print("\nPacket capture completed successfully.")