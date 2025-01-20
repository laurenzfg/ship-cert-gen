from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import datetime

# This library is a Python port of https://github.com/enbility/ship-go/blob/dev/cert/cert.go


def create_certificate(
    organizational_unit: str, organization: str, country: str, common_name: str
):
    private_key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    ski_extension = x509.SubjectKeyIdentifier.from_public_key(
        public_key=private_key.public_key()
    )

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=365 * 10)
        )
        .add_extension(ski_extension, critical=False)
    )

    certificate = cert_builder.sign(private_key=private_key, algorithm=hashes.SHA256())

    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem, ski_extension.digest.hex()


def ski_from_certificate(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        ski = ext.value.digest
        if len(ski) != 20:
            raise ValueError("Client certificate does not provide a SKI")
        return ski.hex()
    except x509.ExtensionNotFound:
        raise ValueError("Client certificate does not provide a SKI")
