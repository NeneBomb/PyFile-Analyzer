# 🔍 PyFile-Analyzer

Herramienta de análisis forense y reputación de archivos escrita en Python. 

## 🛠️ Funcionalidades
- **Smart Detection:** Identifica el tipo de archivo real (Magic Numbers) y detecta scripts (Python, Bash, HTML) analizando su contenido, incluso si no tienen extensión.
- **Integridad:** Genera el hash **SHA-256** del archivo para identificación única.
- **Reputación:** Consulta la API de **VirusTotal** para verificar si el archivo ha sido reportado como malicioso.
- **Multiplataforma:** Funciona en Windows, Linux y macOS.

## 🚀 Instalación
1. Clona el repo.
2. Instala dependencias: `pip install requests filetype python-dotenv colorama`.
3. Crea un archivo `.env` con tu `VT_API_KEY=tu_clave_aqui`.

## 🖥️ Uso
```bash
python3 anapyzer.py
