import socket
from datetime import datetime

def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"[+] Port {port} est OUVERT")
        s.close()
    except KeyboardInterrupt:
        print("\n[!] Interruption par l'utilisateur.")
        exit()
    except socket.error:
        print("[!] Erreur de connexion.")
        exit()


target = input("Entrez l'adresse IP ou le nom de domaine de la cible : ")

# Résolution DNS
try:
    target_ip = socket.gethostbyname(target)
    print(f"[i] IP cible résolue : {target_ip}")
except socket.gaierror:
    print("[!] Erreur : impossible de résoudre le nom.")
    exit()

#  Début du scan
print("-" * 50)
print(f"Début du scan de {target_ip} à {datetime.now()}")
print("-" * 50)


for port in range(1, 1025):
    scan_port(target_ip, port)

print("-" * 50)
print(f"Fin du scan à {datetime.now()}")
print("-" * 50)
