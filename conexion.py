
import json
import os
import gc
import select
import socket
import time
import ssl
import binascii


# ============================================================
# CONFIGURACION
# ============================================================

DIRECTORIO_SCRIPT = os.path.dirname(os.path.abspath(__file__))
ARCHIVO_ENV = os.path.join(DIRECTORIO_SCRIPT, ".env")

ARCHIVO_CONTROL_TRANSMISION = None

RUTA_CERTIFICADOS = None
MQTT_BROKER_ENLACE = None
MQTT_BROKER_PUERTO = None
MQTT_KEEP_ALIVE = None

TIMEOUT_CONEXION = 10
INTERVALO_BUCLE_MS = 100

reinicio_pendiente = None

# ============================================================
# ESTADO
# ============================================================

cliente_mqtt = None
ultimo_ping = 0


# ============================================================
# SERVIDORES NTP
# ============================================================

SERVIDORES_NTP = (
    "pool.ntp.org",
    "time.google.com",
    "time.cloudflare.com",
    "time.windows.com",
)


# ============================================================
# CONFIGURACION DEL DISPOSITIVO
# ============================================================

CAMPOS_CONFIGURACION = (
    "zonaHoraria",
)


# ============================================================
# CARGAR VARIABLES DE ENTORNO
# ============================================================

def cargar_env():
    global RUTA_CERTIFICADOS
    global MQTT_BROKER_ENLACE
    global MQTT_BROKER_PUERTO
    global MQTT_KEEP_ALIVE
    global ARCHIVO_CONTROL_TRANSMISION

    try:
        configuracion = {}

        with open(ARCHIVO_ENV, "r", encoding="utf-8") as archivo:
            for linea in archivo:
                if "=" in linea and not linea.strip().startswith("#"):
                    clave, valor = linea.split("=", 1)
                    configuracion[clave.strip()] = (
                        valor.split("#", 1)[0].strip().strip('"\'')
                    )

        ruta_base = configuracion["RUTA_BASE"].rstrip("/")

        RUTA_CERTIFICADOS = os.path.join(
            ruta_base,
            "certificados"
        )

        ARCHIVO_CONTROL_TRANSMISION = os.path.join(
            ruta_base,
            "transmision.activa"
        )

        MQTT_BROKER_ENLACE = configuracion["MQTT_BROKER_ENLACE"]
        MQTT_BROKER_PUERTO = int(
            configuracion["MQTT_BROKER_PUERTO"]
        )
        MQTT_KEEP_ALIVE = int(configuracion["MQTT_KEEP_ALIVE"])

        print(
            "[CONEXION] BROKER {}:{}".format(
                MQTT_BROKER_ENLACE,
                MQTT_BROKER_PUERTO
            )
        )
        print("[CONEXION] CERTIFICADOS:", RUTA_CERTIFICADOS)
        print("[CONEXION] CONTROL RTSP:", ARCHIVO_CONTROL_TRANSMISION)

    except Exception as error:
        print("[CONEXION] ERROR:", error)
        raise SystemExit


# ============================================================
# SINCRONIZAR HORA
# ============================================================

def sincronizar_hora():
    import subprocess

    print("[HORA] COMPROBANDO SINCRONIZACION DEL SISTEMA...")

    try:
        resultado = subprocess.run(
            ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if resultado.returncode == 0:
            sincronizada = resultado.stdout.strip().lower() == "yes"

            if sincronizada:
                print("[HORA] OK:", time.localtime())
                return True

        print("[HORA] El sistema aun no esta sincronizado por NTP.")
        return False

    except Exception as error:
        print("[HORA] ERROR:", error)
        return False


# ============================================================
# OBTENER UUID DEL CERTIFICADO
# ============================================================

def obtener_clave_certificado(ruta_certificados):
    ruta_certificado = os.path.join(
        ruta_certificados,
        "cliente.crt"
    )

    print("[CERT] RUTA:", ruta_certificado)

    try:
        with open(ruta_certificado, "rb") as archivo:
            certificado = archivo.read()

        inicio = certificado.find(b"-----BEGIN CERTIFICATE-----")
        fin = certificado.find(b"-----END CERTIFICATE-----")

        if inicio == -1 or fin == -1:
            raise ValueError("El certificado no tiene formato PEM.")

        inicio += len(b"-----BEGIN CERTIFICATE-----")

        contenido = certificado[inicio:fin]
        contenido = (
            contenido
            .replace(b"\r", b"")
            .replace(b"\n", b"")
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

        if not posiciones:
            raise ValueError("No se encontro el CN en el certificado.")

        for posicion in reversed(posiciones):
            inicio_busqueda = posicion + len(marcador_cn)
            fin_busqueda = min(
                inicio_busqueda + 100,
                len(datos) - 35
            )

            for indice in range(inicio_busqueda, fin_busqueda):
                posible_uuid = datos[indice:indice + 36]

                if (
                    posible_uuid[8:9] == b"-"
                    and posible_uuid[13:14] == b"-"
                    and posible_uuid[18:19] == b"-"
                    and posible_uuid[23:24] == b"-"
                ):
                    try:
                        clave = posible_uuid.decode("ascii").upper()

                        if len(clave) == 36:
                            print("[CERT] CN:", clave)
                            return clave

                    except Exception:
                        pass

        raise ValueError("No se encontro una clave UUID valida en el CN.")

    except Exception as error:
        raise ValueError(
            "No fue posible obtener la clave del certificado: {}".format(
                error
            )
        )


# ============================================================
# CONTROL DE TRANSMISION RTSP
# ============================================================

def iniciar_transmision():
    """
    Activa la señal que camara.py consulta para iniciar RTSP.
    No detiene ni modifica la grabacion local.
    """

    if not ARCHIVO_CONTROL_TRANSMISION:
        raise RuntimeError(
            "No se ha configurado el archivo de control RTSP."
        )

    clave = obtener_clave_certificado(
        RUTA_CERTIFICADOS
    ).lower()

    temporal = ARCHIVO_CONTROL_TRANSMISION + ".tmp"

    try:
        with open(temporal, "w", encoding="utf-8") as archivo:
            archivo.write(clave)

        # Sustitucion atomica para que camara.py no lea
        # un archivo parcialmente escrito.
        os.replace(temporal, ARCHIVO_CONTROL_TRANSMISION)

        print("[RTSP] Solicitud de inicio enviada a camara.py")
        return True

    finally:
        if os.path.exists(temporal):
            os.remove(temporal)


def detener_transmision():
    """
    Elimina la señal de transmision para que camara.py
    cierre la salida RTSP. La grabacion local continua.
    """

    if not ARCHIVO_CONTROL_TRANSMISION:
        raise RuntimeError(
            "No se ha configurado el archivo de control RTSP."
        )

    try:
        os.remove(ARCHIVO_CONTROL_TRANSMISION)
    except FileNotFoundError:
        pass

    print("[RTSP] Solicitud de detencion enviada a camara.py")
    return True


# ============================================================
# ENVIAR PAQUETE MQTT COMPLETO
# ============================================================

def enviar_paquete(cliente, paquete):
    enviados = 0
    longitud = len(paquete)

    while enviados < longitud:
        cantidad = cliente.send(paquete[enviados:])

        if cantidad is None or cantidad <= 0:
            raise OSError(
                "No se pudo completar el envio del paquete MQTT."
            )

        enviados += cantidad


# ============================================================
# LEER PAQUETE MQTT COMPLETO
# ============================================================

def leer_paquete(cliente):
    cabecera = cliente.recv(1)

    if not cabecera:
        raise OSError("El broker cerro la conexion.")

    multiplicador = 1
    longitud = 0

    while True:
        byte = cliente.recv(1)

        if not byte:
            raise OSError("El broker cerro la conexion.")

        byte = byte[0]
        longitud += (byte & 127) * multiplicador

        if not (byte & 128):
            break

        multiplicador *= 128

        if multiplicador > 128 ** 3:
            raise ValueError("Longitud MQTT invalida.")

    datos = bytearray()

    while len(datos) < longitud:
        bloque = cliente.recv(longitud - len(datos))

        if not bloque:
            raise OSError("El broker cerro la conexion.")

        datos.extend(bloque)

    return cabecera[0], datos


# ============================================================
# CERRAR SOCKET
# ============================================================

def cerrar_socket(cliente):
    if cliente is None:
        return

    try:
        cliente.close()
    except Exception:
        pass


# ============================================================
# CONECTAR MQTT MEDIANTE TLS
# ============================================================

def conectar_mqtt():
    global cliente_mqtt
    global ultimo_ping

    host = MQTT_BROKER_ENLACE
    puerto = MQTT_BROKER_PUERTO

    cliente_id = obtener_clave_certificado(
        RUTA_CERTIFICADOS
    )

    topic = "solicitud/+/{}".format(cliente_id.lower())

    ruta = RUTA_CERTIFICADOS.rstrip("/")
    ca = os.path.join(ruta, "ca.crt")
    certificado = os.path.join(ruta, "cliente.crt")
    llave = os.path.join(ruta, "cliente.key")

    cliente = None

    try:
        print(
            "[MQTT] CONECTANDO {}:{}".format(
                host,
                puerto
            )
        )

        cliente = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        cliente.settimeout(TIMEOUT_CONEXION)
        cliente.connect((host, puerto))

        gc.collect()

        contexto = ssl.SSLContext(
            ssl.PROTOCOL_TLS_CLIENT
        )

        contexto.verify_mode = ssl.CERT_REQUIRED
        contexto.load_verify_locations(ca)
        contexto.load_cert_chain(certificado, llave)

        cliente = contexto.wrap_socket(
            cliente,
            server_hostname=host
        )

        # ----------------------------------------------------
        # CONSTRUIR MQTT CONNECT
        # ----------------------------------------------------

        cliente_id_bytes = cliente_id.encode("utf-8")

        cuerpo = bytearray(b"\x00\x04MQTT")
        cuerpo.extend((4, 2))
        cuerpo.extend(MQTT_KEEP_ALIVE.to_bytes(2, "big"))
        cuerpo.extend(len(cliente_id_bytes).to_bytes(2, "big"))
        cuerpo.extend(cliente_id_bytes)

        paquete = bytearray((0x10,))
        longitud = len(cuerpo)

        while True:
            byte = longitud % 128
            longitud //= 128

            if longitud > 0:
                byte |= 128

            paquete.append(byte)

            if longitud == 0:
                break

        paquete.extend(cuerpo)
        enviar_paquete(cliente, paquete)

        cabecera, respuesta = leer_paquete(cliente)

        if (
            cabecera >> 4 != 2
            or len(respuesta) != 2
            or respuesta[1] != 0
        ):
            raise ValueError(
                "El broker rechazo MQTT: {}".format(respuesta)
            )

        print("[MQTT] CONECTADO CN={}".format(cliente_id))

        cliente_mqtt = cliente
        ultimo_ping = time.time()

        # ----------------------------------------------------
        # CONSTRUIR MQTT SUBSCRIBE
        # ----------------------------------------------------

        topic_bytes = topic.encode("utf-8")

        cuerpo = bytearray((0, 1))
        cuerpo.extend(len(topic_bytes).to_bytes(2, "big"))
        cuerpo.extend(topic_bytes)
        cuerpo.append(0)  # QoS 0

        paquete = bytearray((0x82,))
        longitud = len(cuerpo)

        while True:
            byte = longitud % 128
            longitud //= 128

            if longitud > 0:
                byte |= 128

            paquete.append(byte)

            if longitud == 0:
                break

        paquete.extend(cuerpo)
        enviar_paquete(cliente, paquete)

        cabecera, respuesta = leer_paquete(cliente)

        if (
            cabecera >> 4 != 9
            or len(respuesta) < 3
            or respuesta[2] == 0x80
        ):
            raise ValueError(
                "El broker rechazo la suscripcion."
            )

        print("[MQTT] SUSCRITO:", topic)

        enviar_datos(cliente)

        return True

    except Exception as error:
        print("[MQTT] ERROR CONEXION:", error)

        cerrar_socket(cliente)
        cliente_mqtt = None

        return False


# ============================================================
# MANTENER CONEXION MQTT
# ============================================================

def mantener_mqtt():
    global cliente_mqtt
    global ultimo_ping

    if cliente_mqtt is None:
        return

    try:
        ahora = time.time()

        if ahora - ultimo_ping >= MQTT_KEEP_ALIVE // 2:
            enviar_paquete(
                cliente_mqtt,
                bytearray((0xC0, 0x00))
            )

            ultimo_ping = ahora

        procesar_paquete(cliente_mqtt)

    except Exception as error:
        print("[MQTT] DESCONECTADO:", repr(error))
        print("[MQTT] TIPO DE ERROR:", type(error).__name__)

        cerrar_socket(cliente_mqtt)
        cliente_mqtt = None

        print("[MQTT] Se intentara reconectar.")


# ============================================================
# PROCESAR PAQUETES Y SOLICITUDES MQTT
# ============================================================

def procesar_paquete(cliente):
    global reinicio_pendiente
    global ultimo_ping

    lectura, _, _ = select.select(
        [cliente],
        [],
        [],
        0
    )

    if not lectura:
        return True

    cabecera, datos = leer_paquete(cliente)
    tipo = cabecera >> 4

    # PINGRESP: respuesta al PINGREQ del cliente.
    if tipo == 13:
        ultimo_ping = time.time()
        # print("[MQTT] PINGRESP RECIBIDO")
        return True

    # DISCONNECT enviado por el broker.
    if tipo == 14:
        raise OSError(
            "El broker envio un paquete MQTT DISCONNECT."
        )

    # Por ahora solo procesamos PUBLISH.
    if tipo != 3:
        print(
            "[MQTT] PAQUETE DE CONTROL RECIBIDO: tipo={}".format(
                tipo
            )
        )
        return True

    if len(datos) < 2:
        raise ValueError("Paquete PUBLISH invalido.")

    longitud_topic = int.from_bytes(datos[0:2], "big")
    inicio_mensaje = 2 + longitud_topic

    if len(datos) < inicio_mensaje:
        raise ValueError("Paquete PUBLISH incompleto.")

    qos = (cabecera >> 1) & 0x03

    if qos != 0:
        raise ValueError(
            "PUBLISH con QoS distinto de cero no implementado."
        )

    topic = datos[2:inicio_mensaje].decode("utf-8")
    mensaje = datos[inicio_mensaje:].decode("utf-8")

    print("[MQTT] RECIBIDO {}: {}".format(topic, mensaje))

    partes = topic.split("/")

    if len(partes) != 3 or partes[0] != "solicitud":
        print("[MQTT] TOPICO NO RECONOCIDO:", topic)
        return True

    operacion = partes[1]
    clave_dispositivo = partes[2].upper()

    # Confirmar que la solicitud corresponde a este dispositivo.
    clave_local = obtener_clave_certificado(
        RUTA_CERTIFICADOS
    ).upper()

    if clave_dispositivo != clave_local:
        print("[MQTT] SOLICITUD PARA OTRO DISPOSITIVO:", topic)
        return True

    topic_respuesta = "respuestas/{}".format(clave_local)

    try:
        datos_solicitud = json.loads(mensaje)

        if not isinstance(datos_solicitud, dict):
            raise ValueError(
                "El mensaje debe contener un objeto JSON."
            )

        if operacion == "obtener-datos":
            import almacenamiento

            datos_dispositivo = almacenamiento.cargar_datos()

            responder(cliente, topic_respuesta, {
                "estatus": True,
                "mensaje": "Datos obtenidos correctamente.",
                "datos": datos_dispositivo
            })

        elif operacion == "iniciar-transmision":
            resultado = iniciar_transmision()

            responder(cliente, topic_respuesta, {
                "estatus": resultado,
                "mensaje": (
                    "Solicitud de inicio de transmision."
                    if resultado
                    else "No se pudo solicitar el inicio de transmision."
                ),
                "datos": {
                    "transmitiendo": resultado
                }
            })

        elif operacion == "detener-transmision":
            resultado = detener_transmision()

            responder(cliente, topic_respuesta, {
                "estatus": resultado,
                "mensaje": (
                    "Solicitud de detencion de transmision ."
                    if resultado
                    else "No se pudo solicitar la detencion de transmision."
                ),
                "datos": {
                    "transmitiendo": not resultado
                }
            })

        elif operacion == "obtener-configuracion":
            configuracion = obtener_configuracion()

            responder(cliente, topic_respuesta, {
                "estatus": True,
                "mensaje": "Configuracion obtenida correctamente.",
                "datos": configuracion
            })

        elif operacion == "actualizar-configuracion":
            print(datos_solicitud)
            actualizar_configuracion(datos_solicitud)

            responder(cliente, topic_respuesta, {
                "estatus": True,
                "mensaje": (
                    "Configuracion guardada. Reiniciando dispositivo."
                )
            })

            reinicio_pendiente = True

        else:
            responder(cliente, topic_respuesta, {
                "estatus": False,
                "mensaje": "Operacion no reconocida: {}.".format(
                    operacion
                )
            })

    except Exception as error:
        print(
            "[MQTT] ERROR PROCESANDO {}: {}".format(
                operacion,
                repr(error)
            )
        )

        responder(cliente, topic_respuesta, {
            "estatus": False,
            "mensaje": str(error)
        })

    return True


# ============================================================
# ENVIAR RESPUESTA MQTT
# ============================================================

def responder(cliente, topic, respuesta):
    mensaje = json.dumps({
        "estatus": respuesta["estatus"],
        "mensaje": respuesta["mensaje"],
        "datos": respuesta.get("datos", {})
    })

    publicar(cliente, topic, mensaje)

    print("[MQTT] RESPUESTA ENVIADA:", mensaje)


# ============================================================
# PUBLICAR MENSAJE MQTT
# ============================================================

def publicar(cliente, topic, mensaje):
    if isinstance(mensaje, str):
        mensaje = mensaje.encode("utf-8")

    topic = topic.encode("utf-8")

    cuerpo = bytearray()
    cuerpo.extend(len(topic).to_bytes(2, "big"))
    cuerpo.extend(topic)
    cuerpo.extend(mensaje)

    paquete = bytearray((0x30,))
    longitud = len(cuerpo)

    while True:
        byte = longitud % 128
        longitud //= 128

        if longitud > 0:
            byte |= 128

        paquete.append(byte)

        if longitud == 0:
            break

    paquete.extend(cuerpo)
    enviar_paquete(cliente, paquete)


# ============================================================
# OBTENER CONFIGURACION
# ============================================================

def obtener_configuracion():
    import almacenamiento

    datos = almacenamiento.cargar_datos()
    configuracion = {}

    for campo in CAMPOS_CONFIGURACION:
        if campo not in datos:
            raise ValueError(
                "Falta el campo {} en datos.json.".format(campo)
            )

        configuracion[campo] = datos[campo]

    return configuracion


# ============================================================
# ACTUALIZAR CONFIGURACION
# ============================================================

def actualizar_configuracion(configuracion):
    import almacenamiento

    if not isinstance(configuracion, dict):
        raise ValueError(
            "La configuracion debe ser un objeto JSON."
        )

    for campo in CAMPOS_CONFIGURACION:
        if campo not in configuracion:
            raise ValueError(
                "Falta el campo obligatorio: {}".format(campo)
            )

    campos_gpio = (
        "gpioRgbRojo",
        "gpioRgbVerde",
        "gpioRgbAzul",
        "gpioBoton",
        "gpioRelevador",
    )

    for campo in campos_gpio:
        valor = configuracion[campo]

        if type(valor) is not int or valor < 0 or valor > 27:
            raise ValueError(
                "{} debe ser un entero entre 0 y 27.".format(campo)
            )

    tolerancia = configuracion["tolerancia"]

    if type(tolerancia) is not int or tolerancia < 0:
        raise ValueError(
            "La tolerancia debe ser un entero mayor o igual a cero."
        )

    zona = configuracion["zonaHoraria"]

    if not isinstance(zona, str) or not zona.strip():
        raise ValueError("La zona horaria es obligatoria.")

    eventos = configuracion["eventos"]

    if not isinstance(eventos, list):
        raise ValueError("Los eventos deben ser una lista.")

    for indice, evento in enumerate(eventos):
        if not isinstance(evento, dict):
            raise ValueError(
                "El evento {} no es un objeto valido.".format(indice)
            )

        fecha = evento.get("fecha")

        if not isinstance(fecha, str) or not fecha.strip():
            raise ValueError(
                "El evento {} requiere una fecha valida.".format(indice)
            )

        if evento.get("accion") not in ("A", "D"):
            raise ValueError(
                "La accion del evento {} debe ser A o D.".format(indice)
            )

    def cambiar(datos):
        for campo in CAMPOS_CONFIGURACION:
            datos[campo] = configuracion[campo]

        return True

    resultado = almacenamiento.modificar_datos(cambiar)

    if resultado is not True:
        raise OSError(
            "No se pudo confirmar el guardado de la configuracion."
        )


# ============================================================
# REINICIAR DISPOSITIVO
# ============================================================

def reiniciar_dispositivo():
    try:
        import machine

        print("[SISTEMA] REINICIANDO ESP32...")
        time.sleep(2)
        machine.reset()

    except ImportError:
        print("[SISTEMA] REINICIANDO RASPBERRY PI...")

        os.sync()
        resultado = os.system("sudo -n reboot")

        if resultado != 0:
            raise OSError(
                "No se pudo reiniciar Linux. Verifica los permisos "
                "de sudo para el usuario del servicio."
            )


# ============================================================
# ENVIAR ESTATUS DEL DISPOSITIVO
# ============================================================

def enviar_datos(cliente):
    import almacenamiento

    datos = almacenamiento.cargar_datos()

    cliente_id = obtener_clave_certificado(
        RUTA_CERTIFICADOS
    )

    topic = "datos/{}".format(cliente_id)
    mensaje = json.dumps(datos, ensure_ascii=False)

    publicar(cliente, topic, mensaje)

    print("[MQTT] DATOS ENVIADOS:", mensaje)


# ============================================================
# ACTUALIZAR ESTATUS EN DATOS.JSON
# ============================================================

def actualizar_estatus(estatus):
    import almacenamiento

    def cambiar(datos):
        estatus_anterior = datos["estatus"]
        datos["estatus"] = estatus
        return estatus_anterior

    return almacenamiento.modificar_datos(cambiar)


# ============================================================
# EJECUCION PRINCIPAL
# ============================================================

def ejecutar(
    con_control=None,
    intervalo_ms=INTERVALO_BUCLE_MS
):
    global cliente_mqtt
    global reinicio_pendiente

    cargar_env()

    hora_sincronizada = False

    def actualizar_control():
        if con_control is None:
            return

        con_control(
            True,
            True,
            cliente_mqtt is not None,
            hora_sincronizada,
        )

    while True:
        if cliente_mqtt is None:
            if not hora_sincronizada:
                if sincronizar_hora():
                    hora_sincronizada = True
                    print("[HORA] SINCRONIZADA")
                else:
                    print("[HORA] Reintentando en 2 segundos...")
                    actualizar_control()
                    time.sleep(2)
                    continue

            print("[MQTT] INTENTANDO CONECTAR")

            if conectar_mqtt():
                print("[MQTT] CONEXION ESTABLECIDA")
            else:
                print("[MQTT] Reintentando en 3 segundos...")
                actualizar_control()
                time.sleep(3)
                continue

        else:
            mantener_mqtt()

        if reinicio_pendiente:
            reinicio_pendiente = False

            print("[SISTEMA] Cerrando MQTT antes del reinicio...")

            if cliente_mqtt is not None:
                cerrar_socket(cliente_mqtt)
                cliente_mqtt = None

            actualizar_control()
            time.sleep(2)

            reiniciar_dispositivo()

        actualizar_control()
        time.sleep(intervalo_ms / 1000)
