
import json
import os
import threading


RUTA_BASE = os.path.dirname(os.path.abspath(__file__))
ARCHIVO_DATOS = os.path.join(RUTA_BASE, "datos.json")
ARCHIVO_TEMPORAL = os.path.join(RUTA_BASE, "datos.tmp")

_bloqueo = threading.Lock()


def cargar_datos():
    with _bloqueo:
        with open(ARCHIVO_DATOS, "r", encoding="utf-8") as archivo:
            return json.load(archivo)


def guardar_datos(datos):
    with _bloqueo:
        _guardar(datos)


def modificar_datos(modificar):
    with _bloqueo:
        datos = _cargar()
        resultado = modificar(datos)
        _guardar(datos)
        return resultado


def _cargar():
    with open(ARCHIVO_DATOS, "r", encoding="utf-8") as archivo:
        return json.load(archivo)


def _guardar(datos):
    with open(ARCHIVO_TEMPORAL, "w", encoding="utf-8") as archivo:
        json.dump(datos, archivo, ensure_ascii=False, indent=4)
        archivo.write("\n")
        archivo.flush()
        os.fsync(archivo.fileno())

    os.replace(ARCHIVO_TEMPORAL, ARCHIVO_DATOS)
