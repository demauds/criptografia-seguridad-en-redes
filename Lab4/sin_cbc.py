from base64 import b64encode
from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def ajustar_longitud(valor_usuario: str, longitud_objetivo: int, nombre="") -> bytes:
    valor_bytes = valor_usuario.encode("utf-8")
    original_len = len(valor_bytes)

    print(f"\n[{nombre}] Clave ingresada: {valor_usuario}")
    print(f"[{nombre}] Clave ingresada (hex): {valor_bytes.hex()}")

    if original_len < longitud_objetivo:
        faltan = longitud_objetivo - original_len
        valor_bytes = valor_bytes + get_random_bytes(faltan)
        print(f"[{nombre}] 🔸 Clave muy corta ({original_len} bytes). Se rellenó hasta {longitud_objetivo} bytes.")
    elif original_len > longitud_objetivo:
        valor_bytes = valor_bytes[:longitud_objetivo]
        print(f"[{nombre}] ⚠️ Clave muy larga ({original_len} bytes). Se truncó a {longitud_objetivo} bytes.")
    else:
        print(f"[{nombre}] ✅ Clave con longitud correcta ({longitud_objetivo} bytes).")

    print(f"[{nombre}] Clave ajustada (hex): {valor_bytes.hex()}")
    return valor_bytes


def imprimir_hex(nombre, data: bytes):
    print(f"{nombre}: {data.hex()}")


def cifrar_descifrar_des(texto: str, key: bytes):
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(texto.encode("utf-8"), DES.block_size))

    decipher = DES.new(key, DES.MODE_ECB)
    plaintext = unpad(decipher.decrypt(ciphertext), DES.block_size).decode("utf-8")

    return ciphertext, plaintext


def cifrar_descifrar_3des(texto: str, key: bytes):
    key = DES3.adjust_key_parity(key)
    cipher = DES3.new(key, DES3.MODE_ECB)
    ciphertext = cipher.encrypt(pad(texto.encode("utf-8"), DES3.block_size))

    decipher = DES3.new(key, DES3.MODE_ECB)
    plaintext = unpad(decipher.decrypt(ciphertext), DES3.block_size).decode("utf-8")

    return key, ciphertext, plaintext


def cifrar_descifrar_aes(texto: str, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(texto.encode("utf-8"), AES.block_size))

    decipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(decipher.decrypt(ciphertext), AES.block_size).decode("utf-8")

    return ciphertext, plaintext


def main():
    print("=== CIFRADO DEMO DES / 3DES / AES-256 (modo ECB - sin CBC) ===")

    texto = input("\nIngrese el texto a cifrar: ")

    print("\n--- Entradas DES ---")
    key_des_in = input("Clave para DES (8 bytes máx): ")

    print("\n--- Entradas 3DES ---")
    key_3des_in = input("Clave para 3DES (24 bytes máx): ")

    print("\n--- Entradas AES-256 ---")
    key_aes_in = input("Clave para AES-256 (32 bytes máx): ")

    key_des = ajustar_longitud(key_des_in, 8, "DES")
    key_3des_raw = ajustar_longitud(key_3des_in, 24, "3DES")
    key_aes = ajustar_longitud(key_aes_in, 32, "AES-256")

    print("\n=== RESULTADOS ===")

    print("\n--- DES ---")
    ct_des, pt_des = cifrar_descifrar_des(texto, key_des)
    imprimir_hex("Clave DES final", key_des)
    print("Texto cifrado DES (base64):", b64encode(ct_des).decode("utf-8"))
    print("Texto descifrado DES:", pt_des)

    print("\n--- 3DES ---")
    key_3des, ct_3des, pt_3des = cifrar_descifrar_3des(texto, key_3des_raw)
    imprimir_hex("Clave 3DES final (con paridad)", key_3des)
    print("Texto cifrado 3DES (base64):", b64encode(ct_3des).decode("utf-8"))
    print("Texto descifrado 3DES:", pt_3des)

    print("\n--- AES-256 ---")
    imprimir_hex("Clave AES-256 final", key_aes)
    ct_aes, pt_aes = cifrar_descifrar_aes(texto, key_aes)
    print("Texto cifrado AES-256 (base64):", b64encode(ct_aes).decode("utf-8"))
    print("Texto descifrado AES-256:", pt_aes)

    print("\n=== FIN ===")


if __name__ == "__main__":
    main()
