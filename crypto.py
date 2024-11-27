from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from hashlib import sha256
import datetime
import uuid
from constants import MS_OIDS, DEFAULT_KEY_USAGE, DEFAULT_SMIME_CAPABILITIES
from pyasn1.type.univ import Sequence, Integer, OctetString, ObjectIdentifier
from pyasn1.type.namedtype import NamedType, NamedTypes
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode



def _sequence_component(name: str, tag_value: int, type: object, **subkwargs) -> NamedType:
    return NamedType(name, type.subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple,
                            tag_value),
        **subkwargs))


def create_private_key(keysize: int=2048, exp: int=65537) -> rsa.RSAPrivateKey:
    private_key = rsa.generate_private_key(
        public_exponent=exp,
        key_size=keysize
    )
    return private_key


def private_key_bytes(private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())

def public_key_bytes(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1)


def certificate_bytes(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(encoding=serialization.Encoding.PEM,)


def read_pem_certificate(filename: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(data=open(filename, 'rb').read())


def read_private_key(key_filename: str) -> rsa.RSAPrivateKey:
    return load_pem_private_key(open(key_filename, 'rb').read(), password=None)


# not sure this works
def get_public_key_digest(key: rsa.RSAPublicKey) -> bytes:
    return sha256(key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).digest()


def oid_lookup(oid: str) -> str:
    base = {b[0].dotted_string: b[1] for a in [d for d in dir(x509.oid) if d.endswith('OID')] for b in [[getattr(getattr(x509.oid, a), c), c] for c in dir(getattr(x509.oid, a)) if not c.startswith('__')]}
    all = {**base, **{MS_OIDS[a]: a for a in MS_OIDS}} 
    return all[oid] if oid in all else oid

def name_to_oid(oid: str) -> str:
    base = {b[1]: b[0].dotted_string for a in [d for d in dir(x509.oid) if d.endswith('OID')] for b in [[getattr(getattr(x509.oid, a), c), c] for c in dir(getattr(x509.oid, a)) if not c.startswith('__')]}
    all = {**base, **MS_OIDS} 
    return all[oid] if oid in all else oid



class ObjectIdentifierInt(Sequence):
    componentType = NamedTypes(
        NamedType('id', ObjectIdentifier()),
        NamedType('no', Integer()),
    )


class ObjectIdentifierSeq(Sequence):
    componentType = NamedTypes(
        NamedType('id', ObjectIdentifier())
    )


#    0:d=0  hl=2 l=  64 cons: SEQUENCE
#    2:d=1  hl=2 l=  62 cons: cont [ 0 ]
#    4:d=2  hl=2 l=  10 prim: OBJECT            :Microsoft NTDS AD objectSid
#   16:d=2  hl=2 l=  48 cons: cont [ 0 ]
#   18:d=3  hl=2 l=  46 prim: OCTET STRING      :string

#[U] SEQUENCE
#[C] 0x0
#    [U] OBJECT: 1.3.6.1.4.1.311.25.2.1
#    [C] 0x0
#    [U] OCTET STRING: 0xb'' <-SID as binary string here

     #OtherName ::= SEQUENCE {
     #       type-id    szOID_NTDS_OBJECTSID,
     #       value      octet string }


#[U] SEQUENCE
#  [C] 0x0
#    [U] OBJECT: 1.3.6.1.4.1.311.25.2.1
#    [C] 0x0
#      [U] OCTET STRING: 0xb''


# this is not exactly correct since I cant figure out how to tag both components collectively
# but byte patching afterwards seems to fix it
class UserSid(Sequence):
    componentType = NamedTypes(
        _sequence_component('id', 0, ObjectIdentifier(value='1.3.6.1.4.1.311.25.2.1')),
        _sequence_component('value', 0, OctetString())
    )


# cant figure out how to encode this properly so Im cheating
# b'0' + chr(len(userSid) + 18).encode() + b'\xa0>' + b'\x06\n+\x06\x01\x04\x01\x827\x19\x02\x01' + b'\xa00' + b'\x04.' + f'{userSid}'.encode()), 
def build_user_sid(sid: str) -> bytes:
    sidobj = UserSid()
    sidobj['value'] = sid
    objbytes = encode(sidobj)
    enc_sid_len = len(encode(OctetString(value=sid).subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 0))))
    # change length of first component object to 12 (length of ObjectIdentifier) plus length of encoded sid
    return objbytes[0:3] + bytes([enc_sid_len+12]) + objbytes[4:]



def build_smime_capatilities(capabilities: list) -> bytes:
    seq = Sequence()
    for ind in range(0, len(capabilities)):
        oid_data = capabilities[ind]
        if len(oid_data) == 2:
            oid = ObjectIdentifierInt()
            oid['id'] = oid_data[0]
            oid['no'] = oid_data[1]
        else:
            oid = ObjectIdentifierSeq()
            oid['id'] = oid_data[0]
        seq.setComponentByPosition(ind, oid)
    return encode(seq)


def build_app_policies_extension(oids: list) -> bytes:
    seq = Sequence()
    for ind in range(0, len(oids)):
        oid = ObjectIdentifierSeq()
        oid['id'] = oids[ind]
        seq.setComponentByPosition(ind, oid)
    return encode(seq)


def build_key_usage(key_names: list) -> bytes:
    oider = lambda x: getattr(x509.oid.ExtendedKeyUsageOID, x) if x in dir(x509.oid.ExtendedKeyUsageOID) else x509.ObjectIdentifier(name_to_oid(x))
    return [oider(a) for a in key_names]

def build_template_name(template_name: str) -> bytes:
    encoded = template_name.encode('utf-16-be')
    return b'\x1e' + bytes([len(encoded)]) + encoded


def build_name(name: str) -> bytes:
    encoded = f'{name}'.encode()
    return '\x0c' + bytes([len(encoded)]) + encoded


def build_subject_alternative_names(upn: str, mail: str=None) -> list:
    sans = [
        x509.OtherName(type_id=x509.ObjectIdentifier(MS_OIDS['NT_PRINCIPAL_NAME']),
                       value=build_name(upn)),       
    ]
    if mail:
        sans += [x509.RFC822Name(value=f'{mail}')]
    return sans


def build_named_subject(dn: str, mail: str=None) -> x509.Name:
    l = {'CN': 'COMMON_NAME', 'OU': 'ORGANIZATIONAL_UNIT_NAME', 'DC': 'DOMAIN_COMPONENT'}
    nc = lambda x: x509.NameAttribute(getattr(NameOID, l[x.split('=')[0]]), x.split('=')[1])
    dn_name = [nc(a) for a in dn.split(',')][::-1]
    if mail:
        dn_name += [x509.NameAttribute(NameOID.EMAIL_ADDRESS, mail)]
    return x509.Name(dn_name)




def generate_ca_certificate(ca_dn: str, private_key: rsa.RSAPrivateKey, exp: int=365*10) -> x509.Certificate:
    one_day = datetime.timedelta(1, 0, 0)
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(build_named_subject(ca_dn))
    builder = builder.issuer_name(build_named_subject(ca_dn))
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




def generate_client_certificate(dn, client_private_key, signing_private_key, ca_name: str, upn: str, userSid: str,
                                signing_ca_cert=None, issuer_dn: str=None, exp: int=365, verify: bool=True, config_naming: str='',
                                mail: str='', template_id: str='', template_major_version: int=None,  
                                template_minor_version: int=None, key_usage: list=DEFAULT_KEY_USAGE, app_cert_policies: bool=True,
                                smime_capabilities: list=DEFAULT_SMIME_CAPABILITIES, template_name: str='') -> x509.Certificate:
    

    one_day = datetime.timedelta(1, 0, 0)
    public_key = client_private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(build_named_subject(dn, mail=mail))
    if signing_ca_cert:
        builder = builder.issuer_name(signing_ca_cert.subject)
    elif issuer_dn:
        builder = builder.issuer_name(build_named_subject(issuer_dn))
    else:
        raise Exception('Must provide either signing CA or an issuer name')
    

    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * exp))
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(public_key)


    if template_id and template_major_version and template_minor_version:
        builder = builder.add_extension(
            x509.MSCertificateTemplate(
                template_id=x509.ObjectIdentifier(template_id),
                major_version=template_major_version,
                minor_version=template_minor_version
            ),
            critical=False
        )


    builder = builder.add_extension(
        x509.ExtendedKeyUsage(build_key_usage(key_usage)), 
        critical=False
    )

    builder = builder.add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=False,
                      key_agreement=False, content_commitment=False, data_encipherment=False,
                      crl_sign=False, encipher_only=False, decipher_only=False), critical=True
    )

    if app_cert_policies:
        app_cert_policy_values = [name_to_oid(a) for a in key_usage]

        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(MS_OIDS['APPLICATION_CERT_POLICIES']), # Microsoft Application Policies Extension
                                    build_app_policies_extension(app_cert_policy_values)), 
                                    critical=False 
        )

    if template_name:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(MS_OIDS['ENROLL_CERTTYPE']),
                                        build_template_name(template_name)),
                                        critical=False
        )


    builder = builder.add_extension(
        x509.UnrecognizedExtension(x509.ObjectIdentifier(MS_OIDS['sMIMECapabilities']), # S/MIME Capabilities
                                   build_smime_capatilities(smime_capabilities)), 
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
            general_names= build_subject_alternative_names(upn, mail=mail)
            ),
        critical=False
    )

    builder = builder.add_extension(
        x509.UnrecognizedExtension(x509.ObjectIdentifier(MS_OIDS['userSID']),
                                build_user_sid(userSid)),
                                critical=False 
    )

    certificate = builder.sign(
        private_key=signing_private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    if signing_ca_cert and verify:
        certificate.verify_directly_issued_by(signing_ca_cert)

    return certificate
