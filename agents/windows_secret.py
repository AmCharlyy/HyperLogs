"""Windows DPAPI protection for agent credentials; no third-party dependency."""
import base64
import ctypes
from ctypes import wintypes
import platform


class DATA_BLOB(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_byte))]


def _blob(data):
    buffer = ctypes.create_string_buffer(data)
    return DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def protect(value):
    if platform.system() != 'Windows':
        raise OSError('DPAPI is available only on Windows')
    source, keep = _blob(value.encode('utf-8'))
    output = DATA_BLOB()
    # Local-machine scope allows the startup task to decrypt after reboot.
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(source), 'HyperLogs Agent', None, None, None, 0x4, ctypes.byref(output)):
        raise ctypes.WinError()
    try:
        return base64.b64encode(ctypes.string_at(output.pbData, output.cbData)).decode('ascii')
    finally:
        ctypes.windll.kernel32.LocalFree(output.pbData)


def unprotect(value):
    if platform.system() != 'Windows':
        raise OSError('DPAPI is available only on Windows')
    source, keep = _blob(base64.b64decode(value, validate=True))
    output = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 0, ctypes.byref(output)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output.pbData, output.cbData).decode('utf-8')
    finally:
        ctypes.windll.kernel32.LocalFree(output.pbData)
