import binascii
import logging
import os
import queue
import re
import signal
import subprocess
import sys
import tempfile
import time
import threading
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from picamera2 import Picamera2
from picamera2.encoders import H264Encoder
from picamera2.outputs import PyavOutput, SplittableOutput, CircularOutput2

# Cuando se ejecuta este archivo directamente, registrar el modulo con el nombre
# "camara" permite que conexion.py acceda a estas mismas colas compartidas.
if __name__ == "__main__":
    sys.modules["camara"] = sys.modules[__name__]


# ============================================================
# CONFIGURACION
# ============================================================

DIRECTORIO_SCRIPT = Path(__file__).resolve().parent
ARCHIVO_ENV = DIRECTORIO_SCRIPT / ".env"

if not ARCHIVO_ENV.is_file():
    raise FileNotFoundError(f"No se encontro el archivo .env: {ARCHIVO_ENV}")

load_dotenv(ARCHIVO_ENV, override=True)



def obtener_variable(nombre):
    valor = os.getenv(nombre)
    if valor is None or not valor.strip():
        raise ValueError(f"La variable obligatoria {nombre} no esta definida en .env")
    return valor.strip()


def obtener_entero(nombre):
    try:
        return int(obtener_variable(nombre))
    except ValueError as error:
        raise ValueError(f"La variable {nombre} debe ser un entero") from error


def obtener_decimal(nombre):
    try:
        return float(obtener_variable(nombre))
    except ValueError as error:
        raise ValueError(f"La variable {nombre} debe ser numerica") from error


RUTA_BASE = Path(obtener_variable("RUTA_BASE")).expanduser().resolve()
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
    raise ValueError("ALMACENAMIENTO_MAX_GB y SEGMENTO_MINUTOS deben ser mayores que cero")
if BITRATE_MBPS <= 0 or ANCHO <= 0 or ALTO <= 0 or FPS <= 0:
    raise ValueError("BITRATE_MBPS, ANCHO, ALTO y FPS deben ser mayores que cero")
if not 1 <= MEDIAMTX_PUERTO <= 65535:
    raise ValueError("MEDIAMTX_PUERTO debe estar entre 1 y 65535")

DURACION_SEGMENTO = SEGMENTO_MINUTOS * 60
DIRECTORIO_GRABACIONES = RUTA_BASE / "grabaciones"
DIRECTORIO_EVENTOS = RUTA_BASE / "eventos"
ARCHIVO_CONTROL_TRANSMISION = RUTA_BASE / "transmision.activa"

DIRECTORIO_GRABACIONES.mkdir(parents=True, exist_ok=True)
DIRECTORIO_EVENTOS.mkdir(parents=True, exist_ok=True)


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
    manejador_archivo = logging.FileHandler(ruta_log, encoding="utf-8")
    manejador_archivo.setFormatter(formato_log)
    logger.addHandler(manejador_archivo)
    fecha_log_activa = fecha_actual


# ============================================================
# IDENTIDAD DEL DISPOSITIVO: CN DEL CERTIFICADO
# ============================================================

def obtener_clave_certificado(ruta_certificados):
    ruta_certificado = str(ruta_certificados / "cliente.crt")
    print("[CERT] RUTA:", ruta_certificado)

    try:
        with open(ruta_certificado, "rb") as archivo:
            certificado = archivo.read()

        inicio = certificado.find(b"-----BEGIN CERTIFICATE-----")
        fin = certificado.find(b"-----END CERTIFICATE-----")
        if inicio == -1 or fin == -1 or fin <= inicio:
            raise ValueError("El certificado no tiene formato PEM.")

        inicio += len(b"-----BEGIN CERTIFICATE-----")
        contenido = certificado[inicio:fin]
        contenido = (
            contenido.replace(b"\r", b"")
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
            rb"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
            rb"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
        )

        for posicion in reversed(posiciones):
            inicio_busqueda = posicion + len(marcador_cn)
            fragmento = datos[inicio_busqueda:min(inicio_busqueda + 100, len(datos))]
            for posible_uuid in patron_uuid.findall(fragmento):
                clave = posible_uuid.decode("ascii").lower()
                print("[CERT] CN:", clave.upper())
                return clave

        with tempfile.NamedTemporaryFile(suffix=".crt") as temporal:
            temporal.write(certificado)
            temporal.flush()
            resultado = subprocess.run(
                ["openssl", "x509", "-in", temporal.name, "-noout", "-subject", "-nameopt", "RFC2253"],
                capture_output=True, text=True, check=True, timeout=5,
            )

        coincidencia = re.search(
            r"(?:^|,)CN=([0-9A-Fa-f-]{36})(?:,|$)",
            resultado.stdout.strip(),
        )
        if coincidencia:
            clave = coincidencia.group(1).lower()
            if re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                clave,
            ):
                print("[CERT] CN:", clave.upper())
                return clave

        raise ValueError("No se encontro una clave UUID valida en el CN.")
    except Exception as error:
        raise ValueError(f"No fue posible obtener la clave del certificado: {error}") from error


CLAVE_DISPOSITIVO = obtener_clave_certificado(RUTA_CERTIFICADOS)
URL_MEDIAMTX = f"rtsp://{MEDIAMTX_HOST}:{MEDIAMTX_PUERTO}/{CLAVE_DISPOSITIVO}"
URL_VISUALIZACION = f"http://{MEDIAMTX_HOST}:8889/{CLAVE_DISPOSITIVO}/"




# ============================================================
# TRANSMISION HISTORICA
# ============================================================

proceso_historico = None
bloqueo_historico = threading.Lock()

URL_RTSP_HISTORICO = (
    f"rtsp://{MEDIAMTX_HOST}:{MEDIAMTX_PUERTO}/"
    f"{CLAVE_DISPOSITIVO}/historico"
)

URL_WEBRTC_HISTORICO = (
    f"http://{MEDIAMTX_HOST}:8889/"
    f"{CLAVE_DISPOSITIVO}/historico/"
)



# ============================================================
# CONTROL DE TRANSMISION
# ============================================================

def iniciar_transmision():
    try:
        RUTA_BASE.mkdir(parents=True, exist_ok=True)
        temporal = ARCHIVO_CONTROL_TRANSMISION.with_suffix(".tmp")
        temporal.write_text(CLAVE_DISPOSITIVO, encoding="utf-8")
        os.replace(temporal, ARCHIVO_CONTROL_TRANSMISION)
        logger.info("Solicitud de inicio de transmision: %s", URL_MEDIAMTX)
        return True
    except Exception:
        logger.exception("No se pudo solicitar el inicio de la transmision")
        return False


def detener_transmision():
    try:
        ARCHIVO_CONTROL_TRANSMISION.unlink(missing_ok=True)
        logger.info("Solicitud de detener transmision")
        return True
    except Exception:
        logger.exception("No se pudo solicitar la detencion de la transmision")
        return False


def transmision_solicitada():
    try:
        if not ARCHIVO_CONTROL_TRANSMISION.is_file():
            return False
        contenido = ARCHIVO_CONTROL_TRANSMISION.read_text(encoding="utf-8").strip().lower()
        return contenido == CLAVE_DISPOSITIVO.lower()
    except OSError:
        return False


# ============================================================
# GRABACIONES LOCALES
# ============================================================

def crear_archivo():
    ahora = datetime.now()
    directorio_dia = DIRECTORIO_GRABACIONES / ahora.strftime("%m") / ahora.strftime("%d")
    directorio_dia.mkdir(parents=True, exist_ok=True)
    return directorio_dia / (ahora.strftime("%Y%m%d_%H%M%S_%f") + ".mp4")


def obtener_grabaciones():
    archivos = []
    for archivo in DIRECTORIO_GRABACIONES.rglob("*.mp4"):
        if not archivo.is_file() or archivo.name.endswith(".h265.tmp.mp4"):
            continue
        try:
            archivos.append(archivo)
        except OSError:
            continue
    return sorted(archivos, key=lambda archivo: archivo.stat().st_mtime if archivo.exists() else 0)


# ============================================================
# COLA DE SOLICITUDES DE GRABACIONES
# Debe compartirse con conexion.py dentro del mismo proceso.
# ============================================================

cola_solicitudes_grabaciones = queue.Queue()


def solicitar_busqueda_grabacion(fecha):
    respuesta = queue.Queue(maxsize=1)

    cola_solicitudes_grabaciones.put({
        "accion": "reproducir",
        "fecha": fecha,
        "respuesta": respuesta,
    })

    logger.info(
        "Solicitud de busqueda y reproduccion historica: %s",
        fecha,
    )

    return respuesta

def solicitar_detencion_historica():
    respuesta = queue.Queue(maxsize=1)

    cola_solicitudes_grabaciones.put({
        "accion": "detener",
        "respuesta": respuesta,
    })

    return respuesta

def detener_proceso_historico():
    global proceso_historico

    with bloqueo_historico:
        proceso = proceso_historico
        proceso_historico = None

    if proceso is None:
        return True

    if proceso.poll() is not None:
        logger.info("La reproduccion historica ya habia terminado")
        return True

    logger.info("Deteniendo reproduccion historica anterior")

    try:
        proceso.terminate()

        try:
            proceso.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning("FFmpeg no termino; enviando kill")
            proceso.kill()
            proceso.wait(timeout=5)

        logger.info("Reproduccion historica detenida")
        return True

    except Exception:
        logger.exception("No se pudo detener FFmpeg historico")
        return False

def solicitar_reproduccion_historica(fecha):
    respuesta = queue.Queue(maxsize=1)

    cola_solicitudes_grabaciones.put({
        "accion": "reproducir",
        "fecha": fecha,
        "respuesta": respuesta,
    })

    logger.info(
        "Solicitud de reproduccion historica recibida: %s",
        fecha,
    )

    return respuesta

def buscar_grabacion(fecha_solicitada):
    """Localiza el segmento cerrado que contiene YYYY-MM-DD HH:MM."""

    try:
        fecha = datetime.strptime(
            fecha_solicitada,
            "%Y-%m-%d %H:%M",
        )
    except (TypeError, ValueError) as error:
        raise ValueError(
            "La fecha debe tener el formato YYYY-MM-DD HH:MM."
        ) from error

    directorio = (
        DIRECTORIO_GRABACIONES
        / fecha.strftime("%m")
        / fecha.strftime("%d")
    )

    if not directorio.is_dir():
        logger.info(
            "No existe el directorio de grabaciones: %s",
            directorio,
        )
        return None

    archivos = sorted(
        directorio.glob("*.mp4"),
        reverse=True,
    )

    for archivo in archivos:
        if not archivo.is_file():
            continue

        # Ignorar archivos temporales de compresión.
        if archivo.name.endswith(".tmp.mp4"):
            continue

        # Ignorar archivos que están siendo comprimidos.
        with bloqueo_compresion:
            if archivo.resolve() in archivos_en_compresion:
                continue

        try:
            # El nombre permite conocer el inicio del segmento.
            inicio_archivo = datetime.strptime(
                archivo.stem,
                "%Y%m%d_%H%M%S_%f",
            )

            segundo = (fecha - inicio_archivo).total_seconds()

            # Si la fecha ocurre antes del inicio, no corresponde.
            if segundo < 0:
                continue

            resultado = subprocess.run(
                [
                    "ffprobe",
                    "-v", "error",
                    "-show_entries", "format=duration",
                    "-of", "default=noprint_wrappers=1:nokey=1",
                    str(archivo),
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )

            salida = resultado.stdout.strip()

            if not salida:
                logger.warning(
                    "FFprobe no devolvio duracion para: %s",
                    archivo,
                )
                continue

            duracion = float(salida)

            if not (0 < duracion and segundo < duracion):
                continue

            # Comprobar que el archivo no entró en compresión
            # mientras se consultaba FFprobe.
            with bloqueo_compresion:
                if archivo.resolve() in archivos_en_compresion:
                    continue

            logger.info(
                "Grabacion localizada: %s | segundo %.3f | duracion %.3f",
                archivo.name,
                segundo,
                duracion,
            )

            return {
                "nombre": archivo.name,
                "ruta": str(archivo.resolve()),
                "inicio": inicio_archivo.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "duracion": duracion,
                "segundo": segundo,
            }

        except subprocess.CalledProcessError as error:
            logger.warning(
                "FFprobe no pudo leer %s: %s",
                archivo,
                (error.stderr or "").strip(),
            )
            continue

        except subprocess.TimeoutExpired:
            logger.warning(
                "Tiempo agotado al consultar la grabacion: %s",
                archivo,
            )
            continue

        except (ValueError, OSError, subprocess.SubprocessError):
            logger.exception(
                "Error consultando la grabacion: %s",
                archivo,
            )
            continue

    logger.info(
        "No se encontro una grabacion valida para: %s",
        fecha_solicitada,
    )
    return None


def iniciar_reproduccion_historica(grabacion):
    global proceso_historico

    archivo = Path(grabacion["ruta"]).resolve()
    segundo = float(grabacion["segundo"])

    if not archivo.is_file():
        raise FileNotFoundError(
            f"No existe la grabacion: {archivo}"
        )

    if segundo < 0:
        raise ValueError("El segundo inicial no puede ser negativo")

    # Nunca deben quedar dos publicaciones históricas simultáneas.
    if not detener_proceso_historico():
        raise RuntimeError(
            "No se pudo detener la reproduccion historica anterior"
        )

    comando = [
        "ffmpeg",
        "-hide_banner",
        "-loglevel", "warning",
        "-nostdin",
        "-re",
        "-ss", f"{segundo:.6f}",
        "-i", str(archivo),
        "-map", "0:v:0",
        "-an",
        "-c:v", "libx264",
        "-preset", "ultrafast",
        "-tune", "zerolatency",
        "-pix_fmt", "yuv420p",
        "-f", "rtsp",
        "-rtsp_transport", "tcp",
        URL_RTSP_HISTORICO,
    ]

    logger.info(
        "Iniciando reproduccion historica: %s desde %.2f s",
        archivo,
        segundo,
    )
    logger.info("Publicando historico en: %s", URL_RTSP_HISTORICO)

    proceso = subprocess.Popen(
        comando,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    # Detectar fallos de inicio inmediatos.
    time.sleep(1)

    if proceso.poll() is not None:
        error_ffmpeg = proceso.stderr.read().decode(
            "utf-8",
            errors="replace",
        ) if proceso.stderr else ""

        raise RuntimeError(
            f"FFmpeg termino con codigo {proceso.returncode}: "
            f"{error_ffmpeg}"
        )

    with bloqueo_historico:
        proceso_historico = proceso

    logger.info("Proceso FFmpeg historico iniciado: PID %s", proceso.pid)

    return {
        "rutaRtsp": URL_RTSP_HISTORICO,
        "urlWebRTC": URL_WEBRTC_HISTORICO,
        "pid": proceso.pid,
        "grabacion": grabacion,
    }

def procesar_solicitudes_grabaciones():
    while True:
        try:
            solicitud = cola_solicitudes_grabaciones.get_nowait()
        except queue.Empty:
            return

        respuesta = solicitud["respuesta"]
        accion = solicitud["accion"]

        try:
            if accion == "buscar":
                grabacion = buscar_grabacion(solicitud["fecha"])

                respuesta.put({
                    "estatus": True,
                    "mensaje": (
                        "Grabacion localizada correctamente."
                        if grabacion
                        else "No existe una grabacion para la fecha solicitada."
                    ),
                    "datos": grabacion or {},
                })

            elif accion == "reproducir":
                grabacion = buscar_grabacion(solicitud["fecha"])

                if not grabacion:
                    respuesta.put({
                        "estatus": False,
                        "mensaje": "No existe una grabacion para la fecha solicitada.",
                        "datos": {},
                    })
                    continue

                datos = iniciar_reproduccion_historica(grabacion)

                respuesta.put({
                    "estatus": True,
                    "mensaje": "Publicacion historica iniciada.",
                    "datos": datos,
                })

            elif accion == "detener":
                resultado = detener_proceso_historico()

                respuesta.put({
                    "estatus": resultado,
                    "mensaje": (
                        "Reproduccion historica detenida."
                        if resultado
                        else "No se pudo detener la reproduccion historica."
                    ),
                    "datos": {},
                })

            else:
                raise ValueError(f"Accion desconocida: {accion}")

        except Exception as error:
            logger.exception(
                "Error procesando solicitud historica: %s",
                accion,
            )

            respuesta.put({
                "estatus": False,
                "mensaje": str(error),
                "datos": {},
            })

        finally:
            cola_solicitudes_grabaciones.task_done()
# ============================================================
# COMPRESION H.265
# ============================================================

cola_compresion = queue.Queue()
archivos_en_compresion = set()
bloqueo_compresion = threading.Lock()


def solicitar_compresion(archivo):
    if archivo is None:
        return
    archivo = Path(archivo).resolve()
    with bloqueo_compresion:
        if archivo in archivos_en_compresion:
            return
        archivos_en_compresion.add(archivo)
    cola_compresion.put(archivo)
    logger.info("Grabacion cerrada; en cola para compresion H.265: %s", archivo)


def trabajador_compresion():
    while True:
        archivo = cola_compresion.get()
        try:
            if archivo is None:
                return
            if not archivo.is_file():
                logger.warning("No existe la grabacion para comprimir: %s", archivo)
                continue

            temporal = archivo.with_name(archivo.stem + ".h265.tmp.mp4")
            try:
                tamano_original = archivo.stat().st_size
                if tamano_original == 0:
                    raise RuntimeError("La grabacion original esta vacia.")

                logger.info("Iniciando compresion H.265: %s | %.2f MB", archivo, tamano_original / 1_000_000)
                resultado = subprocess.run(
                    [
                        "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
                        "-i", str(archivo), "-map", "0:v:0", "-map", "0:a?",
                        "-c:v", "libx265", "-preset", "fast", "-crf", "28",
                        "-tag:v", "hvc1", "-c:a", "copy", "-movflags", "+faststart",
                        "-f", "mp4", str(temporal),
                    ],
                    capture_output=True, text=True, timeout=1800,
                )
                if resultado.returncode != 0:
                    raise RuntimeError(resultado.stderr[-3000:] or "FFmpeg termino con error.")
                if not temporal.is_file() or temporal.stat().st_size == 0:
                    raise RuntimeError("FFmpeg no genero un archivo valido.")

                comprobacion = subprocess.run(
                    ["ffprobe", "-v", "error", "-select_streams", "v:0",
                     "-show_entries", "stream=codec_name", "-of", "csv=p=0", str(temporal)],
                    capture_output=True, text=True, timeout=30, check=True,
                )
                if comprobacion.stdout.strip() != "hevc":
                    raise RuntimeError("El archivo resultante no es H.265: " + repr(comprobacion.stdout.strip()))

                tamano_comprimido = temporal.stat().st_size
                # Antes de reemplazar, el temporal debe estar validado.
                os.replace(temporal, archivo)
                reduccion = 100 * (1 - tamano_comprimido / tamano_original)
                logger.info(
                    "COMPRESION H.265 COMPLETADA: %s | %.2f MB -> %.2f MB | reduccion %.1f%%",
                    archivo, tamano_original / 1_000_000, tamano_comprimido / 1_000_000, reduccion,
                )
                limpiar_almacenamiento()
            except subprocess.TimeoutExpired:
                logger.error("Tiempo agotado al comprimir %s. Se conserva el original.", archivo)
            except Exception:
                logger.exception("Fallo al comprimir %s; se conserva el original", archivo)
            finally:
                temporal.unlink(missing_ok=True)
        finally:
            if archivo is not None:
                with bloqueo_compresion:
                    archivos_en_compresion.discard(archivo.resolve())
            cola_compresion.task_done()


# ============================================================
# LIMPIEZA DE ALMACENAMIENTO
# ============================================================

def limpiar_almacenamiento(archivo_activo=None):
    limite_bytes = int(MAX_GB * 1024**3)
    grabaciones = obtener_grabaciones()
    total_bytes = sum(archivo.stat().st_size for archivo in grabaciones if archivo.exists())
    if total_bytes <= limite_bytes:
        return

    logger.info("Limite de almacenamiento: %.2f GB de %.2f GB", total_bytes / 1024**3, MAX_GB)
    for archivo in grabaciones:
        if total_bytes <= limite_bytes:
            break
        if archivo_activo is not None and archivo.resolve() == archivo_activo.resolve():
            continue
        with bloqueo_compresion:
            if archivo.resolve() in archivos_en_compresion:
                continue
        try:
            tamano = archivo.stat().st_size
            archivo.unlink()
            total_bytes -= tamano
            logger.info("Grabacion antigua eliminada: %s", archivo)
        except FileNotFoundError:
            continue
        except OSError:
            logger.exception("No se pudo eliminar la grabacion: %s", archivo)
    logger.info("Almacenamiento utilizado: %.2f GB de %.2f GB", total_bytes / 1024**3, MAX_GB)


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
    salida_local = None
    salida_rtsp = None
    estado_rtsp = False
    hilo_compresion = None
    hilo_mqtt = None

    try:
        actualizar_archivo_log()

        hilo_compresion = threading.Thread(
            target=trabajador_compresion, daemon=True, name="compresion-h265"
        )
        hilo_compresion.start()

        logger.info("Iniciando servicio de camara SGALA")
        logger.info("Ruta base: %s", RUTA_BASE)
        logger.info("UUID del certificado: %s", CLAVE_DISPOSITIVO)
        logger.info("RTSP: %s", URL_MEDIAMTX)
        logger.info("Visualizacion web: %s", URL_VISUALIZACION)
        logger.info("Resolucion: %dx%d", ANCHO, ALTO)
        logger.info("FPS: %d", FPS)
        logger.info("Bitrate de captura H.264: %.2f Mbps", BITRATE_MBPS)
        logger.info("Compresion de grabaciones: H.265 CRF 28")
        logger.info("Duracion de segmento: %d minutos", SEGMENTO_MINUTOS)

        detener_transmision()

        # IMPORTANTE: conexion.ejecutar se ejecuta en este proceso.
        # No usar subprocess.Popen(conexion.py), porque las colas no se comparten.
        # Importar aqui, cuando las colas ya estan definidas, evita una importacion circular.
        import conexion

        hilo_mqtt = threading.Thread(
            target=conexion.ejecutar, daemon=True, name="conexion-mqtt"
        )
        hilo_mqtt.start()
        logger.info("Cliente MQTT iniciado en hilo del proceso de camara")

        camara = Picamera2()
        configuracion = camara.create_video_configuration(
            main={"size": (ANCHO, ALTO), "format": "YUV420"},
            lores={"size": (640, 480), "format": "YUV420"},
            controls={"FrameRate": FPS},
        )
        camara.configure(configuracion)

        encoder = H264Encoder(
            bitrate=int(BITRATE_MBPS * 1_000_000),
            repeat=True,
            iperiod=FPS,
        )

        archivo_activo = crear_archivo()
        salida_local = SplittableOutput(output=PyavOutput(str(archivo_activo)))
        salida_rtsp = CircularOutput2(buffer_duration_ms=1)
        encoder.output = [salida_local, salida_rtsp]

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

            # Procesa las solicitudes en el mismo proceso que conexion.py.
            procesar_solicitudes_grabaciones()

            solicitud_rtsp = transmision_solicitada()
            if solicitud_rtsp and not estado_rtsp:
                try:
                    salida_rtsp.open_output(
                        PyavOutput(URL_MEDIAMTX, format="rtsp", options={"rtsp_transport": "tcp"})
                    )
                    estado_rtsp = True
                    logger.info("Transmision RTSP iniciada: %s", URL_MEDIAMTX)
                except Exception:
                    estado_rtsp = False
                    logger.exception("No se pudo iniciar RTSP; se reintentara")
            elif not solicitud_rtsp and estado_rtsp:
                try:
                    salida_rtsp.close_output()
                    logger.info("Transmision RTSP detenida")
                except Exception:
                    logger.exception("Error al cerrar la salida RTSP")
                finally:
                    estado_rtsp = False

            ahora_monotonic = time.monotonic()
            if ahora_monotonic >= siguiente_segmento:
                archivo_anterior = archivo_activo
                nuevo_archivo = crear_archivo()
                salida_local.split_output(PyavOutput(str(nuevo_archivo)))
                archivo_activo = nuevo_archivo
                logger.info("Nuevo segmento de grabacion: %s", archivo_activo)
                solicitar_compresion(archivo_anterior)
                siguiente_segmento = ahora_monotonic + DURACION_SEGMENTO
                limpiar_almacenamiento(archivo_activo)

            if ahora_monotonic >= siguiente_limpieza:
                limpiar_almacenamiento(archivo_activo)
                siguiente_limpieza = ahora_monotonic + 60

    except KeyboardInterrupt:
        logger.info("Detencion solicitada desde la terminal")
    except Exception:
        logger.exception("Error en el servicio de camara SGALA")
        raise
    finally:
        if salida_rtsp is not None and estado_rtsp:
            try:
                salida_rtsp.close_output()
            except Exception:
                logger.exception("Error al cerrar RTSP durante la detencion")

        if camara is not None:
            if grabando:
                try:
                    camara.stop_encoder(encoder)
                    logger.info("Codificador detenido")
                except Exception:
                    logger.exception("Error al detener el codificador")
            try:
                camara.stop()
            except Exception:
                logger.exception("Error al detener la camara")
            try:
                camara.close()
            except Exception:
                logger.exception("Error al cerrar la camara")

        if archivo_activo is not None and grabando:
            solicitar_compresion(archivo_activo)

        if hilo_compresion is not None:
            logger.info("Esperando a que finalicen las compresiones pendientes")
            cola_compresion.join()

        ARCHIVO_CONTROL_TRANSMISION.unlink(missing_ok=True)

        if manejador_archivo is not None:
            logger.removeHandler(manejador_archivo)
            manejador_archivo.close()

        logger.info("Servicio de camara SGALA finalizado")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, solicitar_detencion)
    ejecutar()
