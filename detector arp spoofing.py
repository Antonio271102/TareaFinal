from scapy.all import ARP, sniff
from collections import defaultdict

# Dirección MAC esperada del router
router_mac = "08:40:f3:db:b8:a0"  # Reemplaza con la MAC de tu router

# Diccionario para almacenar las direcciones MAC conocidas
mac_addresses = defaultdict(str)

def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1, 2):  # who-has or is-at
        arp_src_mac = pkt[ARP].hwsrc
        arp_dst_ip = pkt[ARP].psrc

        if arp_dst_ip == '192.168.5.1':  # Reemplaza con la IP de tu router
            if mac_addresses[arp_dst_ip] != arp_src_mac:
                if mac_addresses[arp_dst_ip] != '':
                    print(f"ARP Spoofing detectado:")
                    print(f"MAC Original: {mac_addresses[arp_dst_ip]}, MAC Modificada: {arp_src_mac}")
                mac_addresses[arp_dst_ip] = arp_src_mac

# Sniffear paquetes ARP
sniff(prn=arp_monitor_callback, filter="arp", store=0)
