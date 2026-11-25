# Gestión de Stock — Posta Rural

Aplicación web para la gestión de inventario, control de lotes bajo criterio **FEFO** (*First Expired, First Out*) y trazabilidad de movimientos en una Posta Rural.

## Alcance del proyecto

* **Etapa 1 (Implementada):**
  * Autenticación y control de acceso por roles (`TENS` y `BODEGA`).
  * **Módulo Bodega:** búsqueda por código de barras, creación de productos e ingreso de lotes.
  * **Módulo Producto:** visualización priorizada por vencimiento (FEFO) y retiro de stock con registro de auditoría en `movimientos`.
* **Etapa 2 (En desarrollo):**
  * **Gestión de Frío:** registro de temperaturas en equipos de frío, alertas y trazabilidad de cadena de frío.

## Tecnologías

* **Backend:** Python + Flask
* **Base de datos:** PostgreSQL (Neon) vía `psycopg2`
* **Frontend:** HTML / CSS
* **Modelado de amenazas:** OWASP Threat Dragon (`ThreatDragonModels/`)

---

## Requisitos previos

* Python 3.10 o superior instalado.
* Una base de datos PostgreSQL (por ejemplo, una cuenta gratuita en [Neon](https://neon.tech/)).

---

## Instalación y puesta en marcha

### 1. Clonar el repositorio
```bash
git clone https://github.com/iSnxw/Proyecto-Stock.git
cd Proyecto-Stock
```

### 2. Crear y activar el entorno virtual
```bash
python -m venv venv
```

* **En Git Bash (Windows):**
  ```bash
  source venv/Scripts/activate
  ```
* **En PowerShell / CMD (Windows):**
  ```bash
  venv\Scripts\activate
  ```
* **En Linux / macOS:**
  ```bash
  source venv/bin/activate
  ```

### 3. Instalar dependencias
```bash
pip install -r requirements.txt
```

### 4. Configurar variables de entorno
Crea tu archivo `.env` a partir de la plantilla `.env.example`:

```bash
cp .env.example .env
```

*(En Windows sin Git Bash, duplica `.env.example` y renómbralo a `.env`).*

Abre `.env` y completa tus credenciales reales:
```env
DATABASE_URL=postgresql://usuario:password@tu-host.neon.tech/neondb?sslmode=require
SECRET_KEY=tu-clave-secreta-larga-y-aleatoria
```

### 5. Crear las tablas en PostgreSQL (Neon)
1. Abre el **SQL Editor** en tu consola de Neon.
2. Copia y ejecuta todo el contenido del archivo **`schema.sql`**.

### 6. Cargar los usuarios y datos iniciales de prueba
Con el entorno virtual `(venv)` activo, ejecuta una sola vez:
```bash
python seed.py
```

> Los correos y contraseñas de prueba (roles `TENS` y `BODEGA`) están definidos en `seed.py`.

### 7. Ejecutar la aplicación
```bash
python app.py
```

Abre en tu navegador `[http://127.0.0.1:5000](http://127.0.0.1:5000)`.