#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
from scapy.all import rdpcap, ICMP, IP

# --- NUEVA SECCIÓN: ANÁLISIS DE FRECUENCIA ---
# Lista de palabras comunes en español para determinar el mensaje más probable.
# Se usan palabras cortas y frecuentes que probablemente aparecerán en un mensaje.
PALABRAS_COMUNES_ES = [
    'el', 'la', 'de', 'que', 'y', 'a', 'en', 'un', 'una', 'los', 'las', 'se', 'no', 'con',
    'para', 'por', 'es', 'del', 'al', 'como', 'mas', 'pero', 'sus', 'le', 'lo', 'ha',
    'mensaje', 'secreto', 'ayuda', 'clave', 'codigo', 'importante', 'datos', 'este'
]

# Códigos de color para la terminal
VERDE = '\033[92m'
RESET = '\033[0m'
# --- FIN DE LA NUEVA SECCIÓN ---


def descifrar_y_mostrar_posibilidades(texto_cifrado):
    """
    Genera todas las 26 posibles combinaciones de un cifrado César,
    evalúa cuál es la más probable y las imprime en la consola.
    """
    print("\n[+] El mensaje parece estar cifrado. Intentando descifrado César...")
    print("----------------------------------------------------------")

    alfabeto = 'abcdefghijklmnopqrstuvwxyz'
    mejor_mensaje = ""
    mejor_puntuacion = -1
    mejor_desplazamiento = -1
    
    posibilidades = []

    # Iteramos por cada posible desplazamiento (de 0 a 25)
    for desplazamiento in range(len(alfabeto)):
        texto_plano = ""
        for char in texto_cifrado:
            if char.lower() in alfabeto:
                # Mantenemos mayúsculas/minúsculas
                es_mayuscula = char.isupper()
                char_lower = char.lower()
                
                # Aplicamos el desplazamiento inverso
                indice_original = alfabeto.find(char_lower)
                indice_descifrado = (indice_original - desplazamiento) % len(alfabeto)
                char_descifrado = alfabeto[indice_descifrado]
                
                if es_mayuscula:
                    texto_plano += char_descifrado.upper()
                else:
                    texto_plano += char_descifrado
            else:
                # Si no es una letra (espacio, número, etc.), la dejamos tal cual
                texto_plano += char

        # Evaluamos qué tan probable es este mensaje
        puntuacion = 0
        palabras_en_mensaje = texto_plano.lower().split()
        for palabra in palabras_en_mensaje:
            if palabra in PALABRAS_COMUNES_ES:
                puntuacion += 1
        
        posibilidades.append((desplazamiento, texto_plano))

        # Si encontramos una mejor opción, la guardamos
        if puntuacion > mejor_puntuacion:
            mejor_puntuacion = puntuacion
            mejor_mensaje = texto_plano
            mejor_desplazamiento = desplazamiento

    # Imprimimos todas las posibilidades, resaltando la mejor
    print("[*] Mostrando todas las posibles combinaciones:")
    for despl, texto in posibilidades:
        if despl == mejor_desplazamiento:
            print(f"{VERDE}[✔] Desplazamiento {despl:2d}: {texto}  <-- Probable mensaje en claro{RESET}")
        else:
            print(f"    Desplazamiento {despl:2d}: {texto}")
    
    print("----------------------------------------------------------")


def extraer_mensaje_correcto(pcap_file):
    """
    Extrae el mensaje oculto de una captura de red, respetando la estructura
    del payload y el orden de los paquetes.
    """
    try:
        paquetes_capturados = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error al leer el archivo pcap: {e}")
        return None

    paquetes_ordenados = {}

    print(f"[*] Analizando {len(paquetes_capturados)} paquetes del archivo '{pcap_file}'...")

    for paquete in paquetes_capturados:
        if paquete.haslayer(ICMP) and paquete.haslayer(IP):
            try:
                payload = bytes(paquete[ICMP].payload)
                seq = paquete[ICMP].seq
                if len(payload) == 56:
                    caracter_byte = payload[8:9]
                    paquetes_ordenados[seq] = caracter_byte.decode('utf-8', errors='ignore')
            except (IndexError, AttributeError, UnicodeDecodeError):
                continue
    
    if not paquetes_ordenados:
        return ""

    mensaje_final = "".join(paquetes_ordenados[seq] for seq in sorted(paquetes_ordenados.keys()))
        
    return mensaje_final


def main():
    pcap_file = "captura.pcapng"
    if not os.path.isfile(pcap_file):
        print(f"Error: No se encontró '{pcap_file}'")
        sys.exit(1)

    mensaje_descubierto = extraer_mensaje_correcto(pcap_file)

    if mensaje_descubierto:
        print("\n---------------------------------")
        print(f"✅ Mensaje Secreto Extraído: {mensaje_descubierto}")
        print("---------------------------------")
        
        # --- LLAMADA A LA NUEVA FUNCIÓN ---
        # Ahora, intentamos descifrar el mensaje
        descifrar_y_mostrar_posibilidades(mensaje_descubierto)
        # ----------------------------------
    else:
        print("\n[!] No se pudo encontrar un mensaje oculto con el formato esperado.")


if __name__ == "__main__":
    main()


    