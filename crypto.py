from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from OpenSSL.crypto import load_certificate, FILETYPE_ASN1, FILETYPE_PEM
import datetime
import uuid



def generate_private_key(keysize=2048, exp=65537):
    private_key = rsa.generate_private_key(
        public_exponent=exp,
        key_size=keysize
    )
    return private_key, private_key.public_key()



def private_key_bytes(private_key):
    return private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())

def public_key_bytes(public_key):
    return public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1)


def certificate_bytes(certificate):
    return certificate.public_bytes(encoding=serialization.Encoding.PEM,)


def load_certificate(filename: str, pem: bool=True):
    ft = FILETYPE_PEM if pem else FILETYPE_ASN1
    return load_certificate(open(filename, 'rb').read(), ft)


def generate_ca_certificate(subject, private_key, exp=365):
    one_day = datetime.timedelta(1, 0, 0)
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject)
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject),
    ]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * exp))
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=False, key_cert_sign=True,
                      key_agreement=False, content_commitment=False, data_encipherment=False,
                      crl_sign=True, encipher_only=False, decipher_only=False), critical=False
    )

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
    )

    builder = builder.add_extension(
        x509.UnrecognizedExtension(x509.ObjectIdentifier('1.3.6.1.4.1.311.21.1'), b'\x02\x01\x00'), critical=False # microsoftCaVersion
    )

    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )



    return certificate

