"""TLS contexts for a private HyperLogs certificate authority."""
from pathlib import Path
import ssl


def verified_context(ca_cert=None):
    if not ca_cert:
        return ssl.create_default_context()
    certificate = Path(ca_cert).expanduser().resolve()
    if not certificate.is_file():
        raise ValueError(f'No se encontró el certificado de HyperLogs: {certificate}')
    return ssl.create_default_context(cafile=str(certificate))
