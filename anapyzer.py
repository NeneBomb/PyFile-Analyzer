import os
import filetype
import hashlib
from colorama import Fore, Style, init

# Inicializamos colores
init(autoreset=True)

def obtener_sha256(ruta):
    """Calcula el hash SHA-256 del archivo (su huella dactilar única)"""
    sha256_hash = hashlib.sha256()
    with open(ruta, "rb") as f:
        # Leemos en trozos para no colapsar la RAM
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def analizar_archivo(ruta):
    # Limpiar la ruta por si viene con comillas de Windows
    ruta = ruta.strip('"').strip("'")

    if not os.path.exists(ruta):
        print(f"{Fore.RED}[!] Error: El archivo no existe.")
        return

    print(f"\n{Fore.CYAN}== ANALIZANDO ARCHIVO ==")
    
    # 1. Identidad Real (Magic Numbers)
    tipo = filetype.guess(ruta)
    if tipo is None:
        tipo_texto = "Desconocido o Texto plano"
        mime_texto = "N/A"
    else:
        tipo_texto = tipo.extension.upper()
        mime_texto = tipo.mime

    # 2. Integridad (Hash)
    hash_f = obtener_sha256(ruta)

    # 3. Mostrar resultados
    print(f"{Fore.YELLOW}Nombre: {Fore.WHITE}{os.path.basename(ruta)}")
    print(f"{Fore.YELLOW}Tipo Real: {Fore.GREEN}{tipo_texto}")
    print(f"{Fore.YELLOW}MIME: {Fore.WHITE}{mime_texto}")
    print(f"{Fore.YELLOW}SHA-256: {Fore.WHITE}{hash_f}")
    print(f"{Fore.CYAN}========================\n")

# Ejecución
if __name__ == "__main__":
    target = input("Arrastra el archivo para analizar: ")
    analizar_archivo(target)
