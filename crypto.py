from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from hashlib import sha256
import datetime
import uuid
from constants import MS_OIDS
from pyasn1.type.univ import Sequence, Integer, OctetString, ObjectIdentifier
from pyasn1.type.namedtype import NamedType, OptionalNamedType, NamedTypes, DefaultedNamedType
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode



def _sequence_component(name, tag_value, type, **subkwargs):
    return NamedType(name, type.subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple,
                            tag_value),
        **subkwargs))


def create_private_key(keysize=2048, exp=65537):
    private_key = rsa.generate_private_key(
        public_exponent=exp,
        key_size=keysize
    )
    return private_key



def private_key_bytes(private_key):
    return private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())

def public_key_bytes(public_key):
    return public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1)


def certificate_bytes(certificate):
    return certificate.public_bytes(encoding=serialization.Encoding.PEM,)

def read_pem_certificate(filename):
    return x509.load_pem_x509_certificate(data=open(filename, 'rb').read())


def read_private_key(key_filename):
    return load_pem_private_key(open(key_filename, 'rb').read(), password=None)


# not sure this works
def get_public_key_digest(key):
    return sha256(key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).digest()


def oid_lookup(oid: str) -> str:
    base = {b[0].dotted_string: b[1] for a in [d for d in dir(x509.oid) if d.endswith('OID')] for b in [[getattr(getattr(x509.oid, a), c), c] for c in dir(getattr(x509.oid, a)) if not c.startswith('__')]}
    all = {**base, **{MS_OIDS[a]: a for a in MS_OIDS}} 
    return all[oid] if oid in all else oid


#    0:d=0  hl=2 l=  64 cons: SEQUENCE
#    2:d=1  hl=2 l=  62 cons: cont [ 0 ]
#    4:d=2  hl=2 l=  10 prim: OBJECT            :Microsoft NTDS AD objectSid
#   16:d=2  hl=2 l=  48 cons: cont [ 0 ]
#   18:d=3  hl=2 l=  46 prim: OCTET STRING      :S-1-5-21-1954401763-2568157779-1971089446-1113

#[U] SEQUENCE
#[C] 0x0
#    [U] OBJECT: 1.3.6.1.4.1.311.25.2.1
#    [C] 0x0
#    [U] OCTET STRING: 0xb'' <-SID as binary string here

     #OtherName ::= SEQUENCE {
     #       type-id    szOID_NTDS_OBJECTSID,
     #       value      octet string }


class Sid(Sequence):
    componentType = NamedTypes(
        _sequence_component("value", 0, OctetString())
    )



class UserSid(Sequence):
    componentType = NamedTypes(
        _sequence_component("typeid", 0, ObjectIdentifier()),
        _sequence_component("sid", 0, OctetString())
    )




#    0:d=0  hl=2 l=   7 cons: SEQUENCE
#    2:d=1  hl=2 l=   1 prim: INTEGER           :7B
#    5:d=1  hl=2 l=   2 prim: cont [ 0 ]







#[U] SEQUENCE
#    [U] SEQUENCE
#        [U] OBJECT: 1.3.6.1.5.5.7.3.2
#    [U] SEQUENCE
#        [U] OBJECT: 1.3.6.1.5.5.7.3.4
#    [U] SEQUENCE
#        [U] OBJECT: 1.3.6.1.4.1.311.10.3.4






def generate_ca_certificate(subject, private_key, exp=365*10):
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
        x509.UnrecognizedExtension(x509.ObjectIdentifier(MS_OIDS['microsoftCaVersion']), b'\x02\x01\x00'), critical=False # microsoftCaVersion
    )

    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )



    return certificate


def generate_client_certificate(subject, client_private_key, signing_private_key, signing_ca_cert=None, issuer_name: str=None,  exp: int=365, verify: bool=True, config_naming: str='', userSid: str='', ca_name: str='', upn: str='', mail: str='', template_id: str=''):
    one_day = datetime.timedelta(1, 0, 0)
    public_key = client_private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject)
    ]))
    if signing_ca_cert:
        builder = builder.issuer_name(signing_ca_cert.subject)
    elif issuer_name:
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
        ]))
    else:
        raise Exception()
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * exp))
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(public_key)

    builder = builder.add_extension(
        x509.MSCertificateTemplate(
            template_id=x509.ObjectIdentifier(template_id),
            major_version=100,
            minor_version=4
        ),
        critical=False
    )

    # TLS Web Client Authentication, E-mail Protection, Microsoft Encrypted File System
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
            x509.ObjectIdentifier(MS_OIDS['EFS_CRYPTO'])
        ]), 
        critical=False
    )

    builder = builder.add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=False,
                      key_agreement=False, content_commitment=False, data_encipherment=False,
                      crl_sign=False, encipher_only=False, decipher_only=False), critical=True
    )


    #[U] SEQUENCE
    #    [U] SEQUENCE
    #        [U] OBJECT: 1.3.6.1.5.5.7.3.2
    #    [U] SEQUENCE
    #        [U] OBJECT: 1.3.6.1.5.5.7.3.4
    #    [U] SEQUENCE
    #        [U] OBJECT: 1.3.6.1.4.1.311.10.3.4

    builder = builder.add_extension(
        x509.UnrecognizedExtension(x509.ObjectIdentifier(MS_OIDS['APPLICATION_CERT_POLICIES']), # Microsoft Application Policies Extension
                                   b'0&0\n\x06\x08+\x06\x01\x05\x05\x07\x03\x020\n\x06\x08+\x06\x01\x05\x05\x07\x03\x040\x0c\x06\n+\x06\x01\x04\x01\x827\n\x03\x04'), 
                                   critical=False 
    )


    #[U] SEQUENCE
    #[U] SEQUENCE
    #    [U] OBJECT: 1.2.840.113549.3.2
    #    [U] INTEGER: 128
    #[U] SEQUENCE
    #    [U] OBJECT: 1.2.840.113549.3.4
    #    [U] INTEGER: 128
    #[U] SEQUENCE
    #    [U] OBJECT: 1.3.14.3.2.7
    #[U] SEQUENCE
    #    [U] OBJECT: 1.2.840.113549.3.7

    builder = builder.add_extension(
        x509.UnrecognizedExtension(x509.ObjectIdentifier(MS_OIDS['sMIMECapabilities']), # S/MIME Capabilities
                                   b'050\x0e\x06\x08*\x86H\x86\xf7\r\x03\x02\x02\x02\x00\x800\x0e\x06\x08*\x86H\x86\xf7\r\x03\x04\x02\x02\x00\x800\x07\x06\x05+\x0e\x03\x02\x070\n\x06\x08*\x86H\x86\xf7\r\x03\x07'), 
                                   critical=False 
    )

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
    )

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_private_key.public_key()), critical=False
    )

    builder = builder.add_extension(
        x509.CRLDistributionPoints(
            [x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(value=f'ldap:///CN={ca_name},CN=DC,CN=CDP,CN=Public%20Key%20Services,CN=Services,{config_naming}?certificateRevocationList?base?objectClass=cRLDistributionPoint')],
                relative_name=None,
                reasons=None,
                crl_issuer=None
                )]
        ), critical=False
    )

    builder = builder.add_extension(
        x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=x509.OID_CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier(value=f'ldap:///CN={ca_name},CN=AIA,CN=Public%20Key%20Services,CN=Services,{config_naming}?cACertificate?base?objectClass=certificationAuthority')
            )
        ]),
        critical=False
    )


    builder = builder.add_extension(
        x509.SubjectAlternativeName(
            general_names=[
                x509.OtherName(type_id=x509.ObjectIdentifier(MS_OIDS['NT_PRINCIPAL_NAME']), value=b'\x0c&' + f'{upn}'.encode()), # upn
                x509.RFC822Name(value=f'{mail}') # mail
            ]
            ),
            
        critical=False
    )


    #[U] SEQUENCE
    #[C] 0x0
    #    [U] OBJECT: 1.3.6.1.4.1.311.25.2.1
    #    [C] 0x0
    #    [U] OCTET STRING: 0xb'' <-SID as binary string here




    builder = builder.add_extension(
        x509.UnrecognizedExtension(x509.ObjectIdentifier(MS_OIDS['userSID']),
                                   b'0' + chr(len(userSid) + 18).encode() + b'\xa0>\x06\n+\x06\x01\x04\x01\x827\x19\x02\x01\xa00\x04.' + f'{userSid}'.encode()), 
                                   critical=False 
    )

    
    certificate = builder.sign(
        private_key=signing_private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    if signing_ca_cert and verify:
        certificate.verify_directly_issued_by(signing_ca_cert)

    return certificate
