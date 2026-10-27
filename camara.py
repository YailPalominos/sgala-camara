
import base64
import binascii
import logging
import os
import re
import signal
import subprocess
import sys
import tempfile
import time

from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from picamera2 import Picamera2
from picamera2.encoders import H264Encoder
from picamera2.outputs import PyavOutput, SplittableOutput, CircularOutput2

import threading
import conexion

hilo_mqtt = threading.Thread(
    target=conexion.ejecutar,
    daemon=True,
    name="conexion-mqtt"
)
hilo_mqtt.start()

# ============================================================
# CONFIGURACION
# ============================================================

DIRECTORIO_SCRIPT = Path(__file__).resolve().parent
ARCHIVO_ENV = DIRECTORIO_SCRIPT / ".env"

if not ARCHIVO_ENV.is_file():
    raise FileNotFoundError(
        f"No se encontro el archivo .env: {ARCHIVO_ENV}"
    )

load_dotenv(ARCHIVO_ENV, override=True)


def obtener_variable(nombre):
    valor = os.getenv(nombre)

    if valor is None or not valor.strip():
        raise ValueError(
            f"La variable obligatoria {nombre} no esta definida en .env"
        )

    return valor.strip()


def obtener_entero(nombre):
    try:
        return int(obtener_variable(nombre))
    except ValueError as error:
        raise ValueError(
            f"La variable {nombre} debe ser un entero"
        ) from error


def obtener_decimal(nombre):
    try:
        return float(obtener_variable(nombre))
    except ValueError as error:
        raise ValueError(
            f"La variable {nombre} debe ser numerica"
        ) from error


RUTA_BASE = Path(
    obtener_variable("RUTA_BASE")
).expanduser().resolve()

RUTA_CERTIFICADOS = RUTA_BASE / "certificados"

MAX_GB = obtener_decimal("ALMACENAMIENTO_MAX_GB")
SEGMENTO_MINUTOS = obtener_entero("SEGMENTO_MINUTOS")
BITRATE_MBPS = obtener_decimal("BITRATE_MBPS")
ANCHO = obtener_entero("ANCHO")
ALTO = obtener_entero("ALTO")
FPS = obtener_entero("FPS")

MEDIAMTX_HOST = obtener_variable("MEDIAMTX_HOST")
MEDIAMTX_PUERTO = obtener_entero("MEDIAMTX_PUERTO")

if MAX_GB <= 0 or SEGMENTO_MINUTOS <= 0:
    raise ValueError(
        "ALMACENAMIENTO_MAX_GB y SEGMENTO_MINUTOS deben ser mayores que cero"
    )

if BITRATE_MBPS <= 0 or ANCHO <= 0 or ALTO <= 0 or FPS <= 0:
    raise ValueError(
        "BITRATE_MBPS, ANCHO, ALTO y FPS deben ser mayores que cero"
    )

if not 1 <= MEDIAMTX_PUERTO <= 65535:
    raise ValueError("MEDIAMTX_PUERTO debe estar entre 1 y 65535")

DURACION_SEGMENTO = SEGMENTO_MINUTOS * 60

DIRECTORIO_GRABACIONES = RUTA_BASE / "grabaciones"
DIRECTORIO_EVENTOS = RUTA_BASE / "eventos"

# Archivo compartido entre camara.py y conexion.py.
ARCHIVO_CONTROL_TRANSMISION = RUTA_BASE / "transmision.activa"


# ============================================================
# REGISTROS
# ============================================================

logger = logging.getLogger("sgala.camara")
logger.setLevel(logging.INFO)
logger.propagate = False

formato_log = logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

if not logger.handlers:
    consola = logging.StreamHandler(sys.stdout)
    consola.setFormatter(formato_log)
    logger.addHandler(consola)

manejador_archivo = None
fecha_log_activa = None


def actualizar_archivo_log():
    global manejador_archivo, fecha_log_activa

    ahora = datetime.now()
    fecha_actual = ahora.strftime("%m/%d")

    if fecha_actual == fecha_log_activa:
        return

    if manejador_archivo is not None:
        logger.removeHandler(manejador_archivo)
        manejador_archivo.close()
        manejador_archivo = None

    directorio_mes = DIRECTORIO_EVENTOS / ahora.strftime("%m")
    directorio_mes.mkdir(parents=True, exist_ok=True)

    ruta_log = directorio_mes / f"{ahora.strftime('%d')}.txt"

    manejador_archivo = logging.FileHandler(
        ruta_log,
        encoding="utf-8",
    )
    manejador_archivo.setFormatter(formato_log)
    logger.addHandler(manejador_archivo)

    fecha_log_activa = fecha_actual


# ============================================================
# IDENTIDAD DEL DISPOSITIVO: CN DEL CERTIFICADO
# ============================================================

def obtener_clave_certificado(ruta_certificados):
    ruta_certificado = "{}/cliente.crt".format(
        str(ruta_certificados).rstrip("/")
    )

    print("[CERT] RUTA:", ruta_certificado)

    try:
        with open(ruta_certificado, "rb") as archivo:
            certificado = archivo.read()

        inicio = certificado.find(
            b"-----BEGIN CERTIFICATE-----"
        )
        fin = certificado.find(
            b"-----END CERTIFICATE-----"
        )

        if inicio == -1 or fin == -1 or fin <= inicio:
            raise ValueError(
                "El certificado no tiene formato PEM."
            )

        inicio += len(b"-----BEGIN CERTIFICATE-----")

        contenido = certificado[inicio:fin]
        contenido = (
            contenido
            .replace(b"\r", b"")
            .replace(b"\n", b"")
            .replace(b" ", b"")
            .replace(b"\t", b"")
        )

        datos = binascii.a2b_base64(contenido)
        marcador_cn = b"\x06\x03\x55\x04\x03"

        posiciones = []
        posicion = 0

        while True:
            posicion = datos.find(marcador_cn, posicion)

            if posicion == -1:
                break

            posiciones.append(posicion)
            posicion += len(marcador_cn)

        patron_uuid = re.compile(
            rb"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-"
            rb"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
            rb"[0-9A-Fa-f]{12}"
        )

        for posicion in reversed(posiciones):
            inicio_busqueda = posicion + len(marcador_cn)
            fin_busqueda = min(inicio_busqueda + 100, len(datos))

            fragmento = datos[inicio_busqueda:fin_busqueda]

            for posible_uuid in patron_uuid.findall(fragmento):
                clave = posible_uuid.decode("ascii").upper()
                print("[CERT] CN:", clave)
                return clave.lower()

        # Alternativa para certificados cuyo contenido no se interpreta
        # correctamente mediante la busqueda binaria anterior.
        with tempfile.NamedTemporaryFile(suffix=".crt") as temporal:
            temporal.write(certificado)
            temporal.flush()

            resultado = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-in",
                    temporal.name,
                    "-noout",
                    "-subject",
                    "-nameopt",
                    "RFC2253",
                ],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )

        sujeto = resultado.stdout.strip()

        coincidencia = re.search(
            r"(?:^|,)CN=([0-9A-Fa-f-]{36})(?:,|$)",
            sujeto,
        )

        if coincidencia:
            clave = coincidencia.group(1).upper()

            if re.fullmatch(
                r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-"
                r"[0-9A-F]{4}-[0-9A-F]{12}",
                clave,
            ):
                print("[CERT] CN:", clave)
                return clave.lower()

        raise ValueError(
            "No se encontro una clave UUID valida en el CN."
        )

    except Exception as error:
        raise ValueError(
            "No fue posible obtener la clave del certificado: {}".format(
                error
            )
        ) from error


# La identidad del dispositivo se obtiene del CN del certificado.
CLAVE_DISPOSITIVO = obtener_clave_certificado(
    RUTA_CERTIFICADOS
)

URL_MEDIAMTX = (
    f"rtsp://{MEDIAMTX_HOST}:{MEDIAMTX_PUERTO}/"
    f"{CLAVE_DISPOSITIVO}"
)

URL_VISUALIZACION = (
    f"http://{MEDIAMTX_HOST}:8889/{CLAVE_DISPOSITIVO}/"
)


# ============================================================
# CONTROL DE TRANSMISION
# Estas funciones pueden importarse desde conexion.py.
# ============================================================

def iniciar_transmision():
    try:
        RUTA_BASE.mkdir(parents=True, exist_ok=True)

        temporal = ARCHIVO_CONTROL_TRANSMISION.with_suffix(".tmp")
        temporal.write_text(
            CLAVE_DISPOSITIVO,
            encoding="utf-8",
        )
        os.replace(temporal, ARCHIVO_CONTROL_TRANSMISION)

        logger.info(
            "Solicitud de inicio de transmision: %s",
            URL_MEDIAMTX,
        )

        return True

    except Exception:
        logger.exception(
            "No se pudo solicitar el inicio de la transmision"
        )
        return False


def detener_transmision():
    try:
        ARCHIVO_CONTROL_TRANSMISION.unlink(missing_ok=True)

        logger.info("Solicitud de detener transmision")
        return True

    except Exception:
        logger.exception(
            "No se pudo solicitar la detencion de la transmision"
        )
        return False


def transmision_solicitada():
    try:
        if not ARCHIVO_CONTROL_TRANSMISION.is_file():
            return False

        contenido = ARCHIVO_CONTROL_TRANSMISION.read_text(
            encoding="utf-8"
        ).strip().lower()

        return contenido == CLAVE_DISPOSITIVO.lower()

    except OSError:
        return False


# ============================================================
# DIRECTORIOS
# ============================================================

DIRECTORIO_GRABACIONES.mkdir(parents=True, exist_ok=True)
DIRECTORIO_EVENTOS.mkdir(parents=True, exist_ok=True)


# ============================================================
# GRABACIONES LOCALES
# ============================================================

def crear_archivo():
    ahora = datetime.now()

    directorio_dia = (
        DIRECTORIO_GRABACIONES
        / ahora.strftime("%m")
        / ahora.strftime("%d")
    )
    directorio_dia.mkdir(parents=True, exist_ok=True)

    nombre = ahora.strftime("%Y%m%d_%H%M%S_%f") + ".mp4"

    return directorio_dia / nombre


def obtener_grabaciones():
    return sorted(
        (
            archivo
            for archivo in DIRECTORIO_GRABACIONES.rglob("*.mp4")
            if archivo.is_file()
        ),
        key=lambda archivo: archivo.stat().st_mtime,
    )


def limpiar_almacenamiento(archivo_activo=None):
    limite_bytes = int(MAX_GB * 1024**3)
    grabaciones = obtener_grabaciones()

    total_bytes = sum(
        archivo.stat().st_size
        for archivo in grabaciones
    )

    if total_bytes <= limite_bytes:
        return

    logger.info(
        "Limite de almacenamiento: %.2f GB de %.2f GB",
        total_bytes / 1024**3,
        MAX_GB,
    )

    for archivo in grabaciones:
        if total_bytes <= limite_bytes:
            break

        if (
            archivo_activo is not None
            and archivo.resolve() == archivo_activo.resolve()
        ):
            continue

        try:
            tamano = archivo.stat().st_size
            archivo.unlink()
            total_bytes -= tamano

            logger.info("Grabacion antigua eliminada: %s", archivo)

        except FileNotFoundError:
            continue

        except OSError:
            logger.exception(
                "No se pudo eliminar la grabacion: %s",
                archivo,
            )

    logger.info(
        "Almacenamiento utilizado: %.2f GB de %.2f GB",
        total_bytes / 1024**3,
        MAX_GB,
    )


# ============================================================
# SERVICIO DE CAMARA
# ============================================================

detener_servicio = False


def solicitar_detencion(signum, frame):
    global detener_servicio

    detener_servicio = True
    logger.info("Se recibio una solicitud de detencion")


def ejecutar():
    global detener_servicio

    camara = None
    encoder = None
    grabando = False
    archivo_activo = None
    salida_rtsp = None
    estado_rtsp = False
    conexion_proceso = None

    try:
        actualizar_archivo_log()

        logger.info("Iniciando servicio de camara SGALA")
        logger.info("Ruta base: %s", RUTA_BASE)
        logger.info("UUID del certificado: %s", CLAVE_DISPOSITIVO)
        logger.info("RTSP: %s", URL_MEDIAMTX)
        logger.info("Visualizacion web: %s", URL_VISUALIZACION)
        logger.info("Resolucion: %dx%d", ANCHO, ALTO)
        logger.info("FPS: %d", FPS)
        logger.info("Bitrate: %.2f Mbps", BITRATE_MBPS)
        logger.info("Duracion de segmento: %d minutos", SEGMENTO_MINUTOS)

        # Comenzar siempre con la transmision desactivada.
        detener_transmision()

        # Iniciar conexion.py si existe en el mismo directorio.
        archivo_conexion = DIRECTORIO_SCRIPT / "conexion.py"

        if archivo_conexion.is_file():
            logger.info("Iniciando proceso MQTT: %s", archivo_conexion)

            conexion_proceso = subprocess.Popen(
                [
                    sys.executable,
                    str(archivo_conexion),
                ],
                cwd=str(DIRECTORIO_SCRIPT),
            )
        else:
            logger.warning(
                "No se encontro conexion.py en %s",
                DIRECTORIO_SCRIPT,
            )

        camara = Picamera2()

        configuracion = camara.create_video_configuration(
            main={
                "size": (ANCHO, ALTO),
                "format": "YUV420",
            },
            lores={
                "size": (640, 480),
                "format": "YUV420",
            },
            controls={
                "FrameRate": FPS,
            },
        )

        camara.configure(configuracion)

        encoder = H264Encoder(
            bitrate=int(BITRATE_MBPS * 1_000_000),
            repeat=True,
            iperiod=FPS,
        )

        # Salida local: siempre activa.
        archivo_activo = crear_archivo()

        salida_local = SplittableOutput(
            output=PyavOutput(str(archivo_activo))
        )

        # Salida remota: CircularOutput2 es una salida valida de Picamera2.
        # El buffer de 1 ms permite reenviar los frames cuando se abre RTSP.
        salida_rtsp = CircularOutput2(buffer_duration_ms=1)

        # Picamera2 acepta una lista de objetos Output.
        encoder.output = [
            salida_local,
            salida_rtsp,
        ]

        camara.start_encoder(encoder)
        camara.start()
        grabando = True

        logger.info("Camara iniciada correctamente")
        logger.info("Grabacion local activa: %s", archivo_activo)
        logger.info("Transmision RTSP inicialmente desactivada")

        siguiente_segmento = time.monotonic() + DURACION_SEGMENTO
        siguiente_limpieza = time.monotonic() + 60

        while not detener_servicio:
            time.sleep(0.2)

            actualizar_archivo_log()

            # Si conexion.py crea el archivo, iniciar RTSP.
            solicitud_rtsp = transmision_solicitada()

            if solicitud_rtsp and not estado_rtsp:
                try:
                    salida_rtsp.open_output(
                        PyavOutput(
                            URL_MEDIAMTX,
                            format="rtsp",
                            options={"rtsp_transport": "tcp"},
                        )
                    )

                    estado_rtsp = True

                    logger.info(
                        "Transmision RTSP iniciada: %s",
                        URL_MEDIAMTX,
                    )

                except Exception:
                    estado_rtsp = False
                    logger.exception(
                        "No se pudo iniciar RTSP; se reintentara"
                    )

            elif not solicitud_rtsp and estado_rtsp:
                try:
                    salida_rtsp.close_output()
                    logger.info("Transmision RTSP detenida")

                except Exception:
                    logger.exception(
                        "Error al cerrar la salida RTSP"
                    )

                finally:
                    estado_rtsp = False

            ahora_monotonic = time.monotonic()

            # Rotar la grabacion local sin detener el encoder.
            if ahora_monotonic >= siguiente_segmento:
                nuevo_archivo = crear_archivo()

                salida_local.split_output(
                    PyavOutput(str(nuevo_archivo))
                )

                archivo_activo = nuevo_archivo

                logger.info(
                    "Nuevo segmento de grabacion: %s",
                    archivo_activo,
                )

                siguiente_segmento = (
                    ahora_monotonic + DURACION_SEGMENTO
                )

                limpiar_almacenamiento(archivo_activo)

            if ahora_monotonic >= siguiente_limpieza:
                limpiar_almacenamiento(archivo_activo)
                siguiente_limpieza = ahora_monotonic + 60

            # Si conexion.py termina, la camara sigue grabando localmente.
            if (
                conexion_proceso is not None
                and conexion_proceso.poll() is not None
            ):
                logger.warning(
                    "El proceso conexion.py termino. "
                    "La grabacion local continuara."
                )
                conexion_proceso = None

    except KeyboardInterrupt:
        logger.info("Detencion solicitada desde la terminal")

    except Exception:
        logger.exception("Error en el servicio de camara SGALA")
        raise

    finally:
        # Cerrar RTSP antes de detener el codificador.
        if salida_rtsp is not None and estado_rtsp:
            try:
                salida_rtsp.close_output()
            except Exception:
                logger.exception(
                    "Error al cerrar RTSP durante la detencion"
                )

        # Detener conexion.py si fue iniciado por este proceso.
        if conexion_proceso is not None:
            try:
                conexion_proceso.terminate()
                conexion_proceso.wait(timeout=5)
            except subprocess.TimeoutExpired:
                conexion_proceso.kill()
                conexion_proceso.wait()
            except Exception:
                logger.exception(
                    "Error al detener conexion.py"
                )

        if camara is not None:
            if grabando:
                try:
                    camara.stop_encoder(encoder)
                    logger.info("Codificador detenido")
                except Exception:
                    logger.exception(
                        "Error al detener el codificador"
                    )

            try:
                camara.stop()
            except Exception:
                logger.exception("Error al detener la camara")

            try:
                camara.close()
            except Exception:
                logger.exception("Error al cerrar la camara")

        # Evitar que una solicitud antigua reactive RTSP en el siguiente inicio.
        try:
            ARCHIVO_CONTROL_TRANSMISION.unlink(missing_ok=True)
        except OSError:
            logger.exception(
                "No se pudo limpiar el archivo de control RTSP"
            )

        if manejador_archivo is not None:
            logger.removeHandler(manejador_archivo)
            manejador_archivo.close()

        logger.info("Servicio de camara SGALA finalizado")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, solicitar_detencion)
    ejecutar()
