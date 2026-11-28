CREATE TABLE IF NOT EXISTS usuarios (
    id SERIAL PRIMARY KEY,
    nombre VARCHAR(120) NOT NULL,
    correo VARCHAR(120) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    rol VARCHAR(20) NOT NULL CHECK (rol IN ('TENS', 'BODEGA')),
    activo BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS productos (
    id SERIAL PRIMARY KEY,
    codigo_barras VARCHAR(64) NOT NULL UNIQUE,
    nombre VARCHAR(150) NOT NULL,
    familia VARCHAR(80) NOT NULL,
    presentacion VARCHAR(60) NOT NULL,
    unidad_medida VARCHAR(30) NOT NULL,
    requiere_frio BOOLEAN NOT NULL DEFAULT FALSE,
    stock_minimo INTEGER NOT NULL DEFAULT 0 CHECK (stock_minimo >= 0),
    activo BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS equipos_frio (
    id SERIAL PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    ubicacion VARCHAR(100) NOT NULL,
    temp_min_c NUMERIC(4,1) NOT NULL DEFAULT 2.0,
    temp_max_c NUMERIC(4,1) NOT NULL DEFAULT 8.0,
    activo BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (temp_max_c > temp_min_c)
);

CREATE TABLE IF NOT EXISTS lotes (
    id SERIAL PRIMARY KEY,
    producto_id INTEGER NOT NULL REFERENCES productos(id),
    equipo_frio_id INTEGER REFERENCES equipos_frio(id),
    numero_lote VARCHAR(60) NOT NULL,
    fecha_vencimiento DATE NOT NULL,
    cantidad_inicial INTEGER NOT NULL CHECK (cantidad_inicial > 0),
    cantidad_actual INTEGER NOT NULL CHECK (cantidad_actual >= 0),
    estado VARCHAR(20) NOT NULL DEFAULT 'DISPONIBLE'
        CHECK (estado IN ('DISPONIBLE', 'AGOTADO', 'CUARENTENA', 'BAJA')),
    UNIQUE (producto_id, numero_lote)
);

CREATE TABLE IF NOT EXISTS registros_frio (
    id SERIAL PRIMARY KEY,
    equipo_frio_id INTEGER NOT NULL REFERENCES equipos_frio(id),
    usuario_id INTEGER NOT NULL REFERENCES usuarios(id),
    temperatura_c NUMERIC(4,1) NOT NULL,
    estado_alerta VARCHAR(15) NOT NULL CHECK (estado_alerta IN ('VERDE', 'AMARILLA', 'ROJA')),
    fecha_registro TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS movimientos (
    id SERIAL PRIMARY KEY,
    lote_id INTEGER NOT NULL REFERENCES lotes(id),
    usuario_id INTEGER NOT NULL REFERENCES usuarios(id),
    registro_frio_id INTEGER REFERENCES registros_frio(id),
    tipo_movimiento VARCHAR(20) NOT NULL
        CHECK (tipo_movimiento IN ('ENTRADA', 'SALIDA', 'AJUSTE_MAS', 'AJUSTE_MENOS', 'CUARENTENA', 'LIBERACION', 'BAJA')),
    cantidad INTEGER NOT NULL CHECK (cantidad >= 0),
    observacion TEXT,
    fecha_registro TIMESTAMPTZ NOT NULL DEFAULT NOW()
);