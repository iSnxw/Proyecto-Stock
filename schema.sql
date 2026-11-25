-- Estructura completa de la base de datos (PostgreSQL / Neon)
-- Proyecto: Gestión de Stock Posta Rural

CREATE TABLE IF NOT EXISTS usuarios (
    id SERIAL PRIMARY KEY,
    nombre VARCHAR NOT NULL,
    correo VARCHAR NOT NULL UNIQUE,
    password_hash VARCHAR NOT NULL,
    rol VARCHAR NOT NULL CHECK (rol IN ('TENS', 'BODEGA')),
    activo BOOLEAN NOT NULL DEFAULT TRUE,
    creado_en TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS equipos_frio (
    id SERIAL PRIMARY KEY,
    nombre VARCHAR NOT NULL,
    ubicacion VARCHAR NOT NULL,
    temp_min_c NUMERIC NOT NULL,
    temp_max_c NUMERIC NOT NULL,
    activo BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (temp_max_c > temp_min_c)
);

CREATE TABLE IF NOT EXISTS productos (
    id SERIAL PRIMARY KEY,
    codigo_barras VARCHAR NOT NULL UNIQUE,
    nombre VARCHAR NOT NULL,
    familia VARCHAR NOT NULL,
    presentacion VARCHAR NOT NULL,
    unidad_medida VARCHAR NOT NULL CHECK (unidad_medida IN ('UNIDAD', 'CAJA', 'FRASCO', 'DOSIS')),
    requiere_frio BOOLEAN NOT NULL DEFAULT FALSE,
    stock_minimo INTEGER NOT NULL CHECK (stock_minimo >= 0),
    activo BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS lotes (
    id SERIAL PRIMARY KEY,
    producto_id INTEGER NOT NULL REFERENCES productos(id),
    equipo_frio_id INTEGER REFERENCES equipos_frio(id),
    numero_lote VARCHAR NOT NULL,
    fecha_vencimiento DATE NOT NULL,
    cantidad_inicial INTEGER NOT NULL CHECK (cantidad_inicial > 0),
    cantidad_actual INTEGER NOT NULL CHECK (cantidad_actual >= 0),
    estado VARCHAR NOT NULL CHECK (estado IN ('DISPONIBLE', 'CUARENTENA', 'BAJA', 'AGOTADO')),
    UNIQUE (producto_id, numero_lote)
);

CREATE TABLE IF NOT EXISTS registros_frio (
    id SERIAL PRIMARY KEY,
    equipo_frio_id INTEGER NOT NULL REFERENCES equipos_frio(id),
    usuario_id INTEGER NOT NULL REFERENCES usuarios(id),
    temperatura_c NUMERIC NOT NULL,
    estado_alerta VARCHAR NOT NULL CHECK (estado_alerta IN ('VERDE', 'AMARILLA', 'ROJA')),
    origen_offline BOOLEAN NOT NULL DEFAULT FALSE,
    id_transaccion_offline UUID UNIQUE,
    fecha_dispositivo TIMESTAMPTZ NOT NULL,
    fecha_servidor TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS movimientos (
    id SERIAL PRIMARY KEY,
    lote_id INTEGER NOT NULL REFERENCES lotes(id),
    usuario_id INTEGER NOT NULL REFERENCES usuarios(id),
    registro_frio_id INTEGER REFERENCES registros_frio(id),
    tipo_movimiento VARCHAR NOT NULL CHECK (tipo_movimiento IN ('ENTRADA', 'SALIDA', 'AJUSTE', 'CUARENTENA', 'LIBERACION', 'BAJA')),
    cantidad INTEGER NOT NULL CHECK (cantidad >= 0),
    observacion TEXT,
    origen_offline BOOLEAN NOT NULL DEFAULT FALSE,
    id_transaccion_offline UUID UNIQUE,
    fecha_dispositivo TIMESTAMPTZ NOT NULL,
    fecha_servidor TIMESTAMPTZ NOT NULL DEFAULT NOW()
);