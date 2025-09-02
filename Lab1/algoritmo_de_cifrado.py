def cifrado_cesar(texto, desplazamiento):
    resultado = ""

    for letra in texto:
        # Solo cifrar letras, dejar otros caracteres sin cambios
        if letra.isalpha():
            # Determinar si la letra es mayúscula o minúscula
            ascii_base = ord('A') if letra.isupper() else ord('a')
            # Aplicar desplazamiento usando módulo 26
            letra_cifrada = chr((ord(letra) - ascii_base + desplazamiento) % 26 + ascii_base)
            resultado += letra_cifrada
        else:
            resultado += letra  # otros caracteres no se modifican

    return resultado

# Programa principal
if __name__ == "__main__":
    texto = input("Ingrese el texto a cifrar: ")
    try:
        desplazamiento = int(input("Ingrese el desplazamiento: "))
        texto_cifrado = cifrado_cesar(texto, desplazamiento)
        print("Texto cifrado:", texto_cifrado)
    except ValueError:
        print("Por favor, ingrese un número válido para el desplazamiento.")
