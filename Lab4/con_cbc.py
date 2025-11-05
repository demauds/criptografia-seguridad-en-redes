
from base64 import b64encode, b64decode
from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def ajustar_longitud(valor_usuario: str, longitud_objetivo: int, nombre="") -> bytes:
    valor_bytes = valor_usuario.encode("utf-8")
    original_len = len(valor_bytes)

    print(f"\n[{nombre}] Clave/IV ingresado: {valor_usuario}")
    print(f"[{nombre}] Ingresado (hex): {valor_bytes.hex()}")

    if original_len < longitud_objetivo:
        faltan = longitud_objetivo - original_len
        valor_bytes = valor_bytes + get_random_bytes(faltan)
        print(f"[{nombre}] 🔸 Muy corto ({original_len} bytes). Se rellenó hasta {longitud_objetivo} bytes.")
    elif original_len > longitud_objetivo:
        valor_bytes = valor_bytes[:longitud_objetivo]
        print(f"[{nombre}] ⚠️ Muy largo ({original_len} bytes). Se truncó a {longitud_objetivo} bytes.")
    else:
        print(f"[{nombre}] ✅ Longitud correcta ({longitud_objetivo} bytes).")

    print(f"[{nombre}] Ajustado (hex): {valor_bytes.hex()}")
    return valor_bytes


def cifrar_descifrar_des(texto: str, key: bytes, iv: bytes):
    
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(texto.encode("utf-8"), DES.block_size))

    decipher = DES.new(key, DES.MODE_CBC, iv)
    pt = unpad(decipher.decrypt(ct), DES.block_size).decode("utf-8")

    return ct, pt


def cifrar_descifrar_3des(texto: str, key: bytes, iv: bytes):
    key = DES3.adjust_key_parity(key)

    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ct = cipher.encrypt(pad(texto.encode("utf-8"), DES3.block_size))

    decipher = DES3.new(key, DES3.MODE_CBC, iv)
    pt = unpad(decipher.decrypt(ct), DES3.block_size).decode("utf-8")

    return key, ct, pt


def cifrar_descifrar_aes(texto: str, key: bytes, iv: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(texto.encode("utf-8"), AES.block_size))

    decipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(decipher.decrypt(ct), AES.block_size).decode("utf-8")

    return ct, pt


def main():
    print("=== CIFRADO / DESCIFRADO CBC ===")
    texto = input("Ingrese el texto a cifrar: ")

    print("\n--- ENTRADAS DES ---")
    key_des_in = input("Clave para DES (se ajustará a 8 bytes): ")
    iv_des_in = input("IV para DES (se ajustará a 8 bytes): ")

    key_des = ajustar_longitud(key_des_in, 8, "DES-KEY")
    iv_des = ajustar_longitud(iv_des_in, 8, "DES-IV")

    ct_des, pt_des = cifrar_descifrar_des(texto, key_des, iv_des)

    print("\n--- ENTRADAS 3DES ---")
    key_3des_in = input("Clave para 3DES (se ajustará a 24 bytes): ")
    iv_3des_in = input("IV para 3DES (se ajustará a 8 bytes): ")

    key_3des_raw = ajustar_longitud(key_3des_in, 24, "3DES-KEY")
    iv_3des = ajustar_longitud(iv_3des_in, 8, "3DES-IV")

    key_3des, ct_3des, pt_3des = cifrar_descifrar_3des(texto, key_3des_raw, iv_3des)

    print("\n--- ENTRADAS AES-256 ---")
    key_aes_in = input("Clave para AES-256 (se ajustará a 32 bytes): ")
    iv_aes_in = input("IV para AES (se ajustará a 16 bytes): ")

    key_aes = ajustar_longitud(key_aes_in, 32, "AES-KEY")
    iv_aes = ajustar_longitud(iv_aes_in, 16, "AES-IV")

    ct_aes, pt_aes = cifrar_descifrar_aes(texto, key_aes, iv_aes)

    print("\n================ RESULTADOS ================")

    print("\n[DES]")
    print("Clave DES final (hex):", key_des.hex())
    print("IV DES final (hex):", iv_des.hex())
    print("Texto cifrado DES (base64):", b64encode(ct_des).decode("utf-8"))
    print("Texto descifrado DES:", pt_des)

    print("\n[3DES]")
    print("Clave 3DES final (hex):", key_3des.hex())
    print("IV 3DES final (hex):", iv_3des.hex())
    print("Texto cifrado 3DES (base64):", b64encode(ct_3des).decode("utf-8"))
    print("Texto descifrado 3DES:", pt_3des)

    print("\n[AES-256]")
    print("Clave AES final (hex):", key_aes.hex())
    print("IV AES final (hex):", iv_aes.hex())
    print("Texto cifrado AES (base64):", b64encode(ct_aes).decode("utf-8"))
    print("Texto descifrado AES:", pt_aes)

    print("\n=== FIN ===")


if __name__ == "__main__":
    main()
