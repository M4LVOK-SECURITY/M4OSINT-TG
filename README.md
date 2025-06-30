
# M4LVOK OSINT Tool V3.0 - All-In-One Edition

**M4LVOK OSINT Tool** es un Framework de Reconocimiento Avanzado para Telegram, diseñado para analistas de inteligencia y profesionales de la seguridad. Esta herramienta de línea de comandos extrae, analiza y correlaciona artefactos digitales de perfiles públicos de Telegram, presentando la información en un dossier táctico y fácil de interpretar.

---

### ⚖️ **Disclaimer / Descargo de Responsabilidad**

> Esta herramienta ha sido creada con fines **estrictamente éticos y educativos**. El usuario es el único responsable del uso que le dé a este software. El autor (**M4LVOK**) no se hace responsable por el mal uso, actividades ilegales o daños que puedan derivarse del uso de esta herramienta. Úsala siempre en entornos controlados, con responsabilidad y respetando la privacidad de las personas.

---

### ✨ **Capacidades del Framework (Checklist de Funciones)**

Esta versión "Todo-en-Uno" incluye todos los módulos desarrollados, sin omitir ninguno:

* **Análisis de Perfil Básico:**
    * [✔] Extracción de Nombre, Biografía y URL de Foto de Perfil (absoluta y completa).
    * [✔] Interfaz de comandos profesional con argumentos (`-u`, `-o`).

* **Análisis de Artefactos Digitales:**
    * [✔] Detección y extracción de **direcciones de Email**.
    * [✔] Detección y extracción de **números de Teléfono**.
    * [✔] **Fingerprinting** del perfil con hashes MD5 y SHA256 para identificación.

* **Módulos de Inteligencia Avanzada:**
    * [✔] **Análisis Telefónico:** Cruce de datos para obtener País/Región y Operador del número encontrado.
    * [✔] **Análisis Profundo de Red:** Resolución de IP, País, Organización y ASN para cada dominio encontrado en la biografía.

* **Capacidades Forenses:**
    * [✔] **Análisis Forense de Imagen:** Intento de extracción de metadatos **EXIF** de la foto de perfil.
    * [✔] **Búsqueda Inversa de Imagen (Spectre):** Generación de un enlace de Google Lens para rastrear la foto de perfil en toda la web y encontrar perfiles coincidentes en otras plataformas (Facebook, Pinterest, etc.).

* **Módulo de Expansión OSINT:**
    * [✔] **Búsqueda Cruzada de Usuario:** Generación de enlaces de búsqueda para encontrar el *nombre de usuario* en Google, Twitter/X, GitHub y más.

* **Reportes y Usabilidad:**
    * [✔] Interfaz visual táctica en la terminal con barras de progreso y logs con timestamp.
    * [✔] Generación de un **dossier completo en formato JSON** para análisis posterior.

---

### 📦 **Instalación (Deployment)**

Asegúrate de tener `Python 3` y `Git` instalados.

1.  **Clona el repositorio:**
    ```bash
    git clone https://github.com/M4LVOK-SECURITY/M4OSINT-TG
    cd M4OSINT-TG
    ```
2.  **(Recomendado) Crea y activa un entorno virtual:**

    * **En Windows:**
        ```cmd
        python -m venv venv
        .\venv\Scripts\activate
        ```
    * **En Linux / macOS:**
        ```bash
        python3 -m venv venv
        source venv/bin/activate
        ```

3.  **Instala todas las dependencias:**
    El archivo `requirements.txt` contiene todas las librerías necesarias.
    ```bash
    pip install -r requirements.txt
    ```

---

### 🚀 **Uso (Execution)**

Utiliza la herramienta desde la terminal. El argumento `-u` para el nombre de usuario es **obligatorio**.

* **Análisis básico de un objetivo:**
    ```bash
    python m4osint.py -u <nombredeusuario>
    ```
    *Ejemplo:* `python m4osint.py -u @m4lvok`

* **Análisis con guardado de reporte en JSON:**
    ```bash
    python m4osint.py -u <nombredeusuario> -o <nombre_del_archivo.json>
    ```
    *Ejemplo:* `python m4osint.py -u PavelDurov -o dossier_durov.json`

* **Ver el panel de ayuda:**
    ```bash
    python m4osint.py --help
    ```

---

⚖️ Licencia
Este proyecto está distribuido bajo la Licencia MIT. Consulta el archivo LICENSE para más detalles.
