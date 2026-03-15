import os
import filetype
import hashlib
import requests
from dotenv import load_dotenv
from colorama import Fore, Style, init

# Cargamos la API Key desde el .env
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

# Inicializamos colores
init(autoreset=True)

def obtener_sha256(ruta):
    """Calcula el hash SHA-256 del archivo"""
    sha256_hash = hashlib.sha256()
    try:
        with open(ruta, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return None

def consultar_virustotal(file_hash):
    """Consulta la reputación del hash en VirusTotal"""
    if not API_KEY or API_KEY == "tu_clave_aqui_sin_comillas":
        return f"{Fore.YELLOW}Clave API no configurada en .env"

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            # Extraemos los resultados de los análisis
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            suspicious = stats['suspicious']
            undiscovered = stats['undetected']
            
            color = Fore.GREEN if malicious == 0 else Fore.RED
            return f"{color}{malicious} motores detectaron malware (de {malicious + undiscovered} analizados)"
        elif response.status_code == 404:
            return f"{Fore.BLUE}Archivo no encontrado en la DB de VirusTotal (puede ser limpio o muy nuevo)"
        else:
            return f"{Fore.RED}Error en API: {response.status_code}"
    except Exception as e:
        return f"{Fore.RED}Error de conexión: {str(e)}"

def analizar_archivo(ruta):
    ruta = ruta.strip('"').strip("'").strip()

    if not os.path.exists(ruta):
        print(f"{Fore.RED}[!] Error: El archivo no existe.")
        return

    print(f"\n{Fore.CYAN}== ANALIZANDO ARCHIVO ==")
    
    # 1. Magic Numbers
    tipo = filetype.guess(ruta)
    tipo_texto = tipo.extension.upper() if tipo else "Desconocido/Texto"
    mime_texto = tipo.mime if tipo else "N/A"

    # 2. Hash
    hash_f = obtener_sha256(ruta)

    # 3. VirusTotal
    print(f"{Fore.YELLOW}Consultando VirusTotal... (espera)")
    resultado_vt = consultar_virustotal(hash_f)

    # 4. Mostrar resultados finales
    print(f"{Fore.YELLOW}Nombre: {Fore.WHITE}{os.path.basename(ruta)}")
    print(f"{Fore.YELLOW}Tipo Real: {Fore.GREEN}{tipo_texto}")
    print(f"{Fore.YELLOW}MIME: {Fore.WHITE}{mime_texto}")
    print(f"{Fore.YELLOW}SHA-256: {Fore.WHITE}{hash_f}")
    print(f"{Fore.YELLOW}Reputación: {resultado_vt}")
    print(f"{Fore.CYAN}========================\n")

if __name__ == "__main__":
    target = input("Arrastra el archivo para analizar: ")
    analizar_archivo(target)
