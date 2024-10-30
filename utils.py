import argparse
import sys
import os
import logging
import tempfile
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from impacket.ldap.ldaptypes import ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, LDAP_SID, SR_SECURITY_DESCRIPTOR, ACL, ACCESS_ALLOWED_ACE
from impacket.uuid import string_to_bin



KRB_CONF_TEMPLATE = '''
[libdefaults]
    default_realm = [REALM]
    
[realms]
    [REALM] = {
        kdc = [KDC]
    }
'''



class MyParser(argparse.ArgumentParser):
    """
    Custom argument parser
    """
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)




def create_logger(loglevel: str, name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(loglevel)
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


# creates a kerberos config file and configures it for use
# only required when your workstation cannot identify the KDC via DNS
def create_kerberos_config(realm, kdc):
    template = KRB_CONF_TEMPLATE.replace('[REALM]', realm.upper()).replace('[KDC]', kdc).replace('[REALM_LOWER]', realm.lower())
    krb_config = os.path.join(tempfile.gettempdir(), 'krb5.conf')
    open(krb_config, 'w').write(template)
    os.environ["KRB5_CONFIG"] = krb_config
    return krb_config



class PKCS12Cert:
    '''Object representing PKCS12 cert allowing extraction of useful data'''
    def __init__(self, pkcsfile):
        try:
            certdata = open(pkcsfile, 'rb').read()
            p12 = pkcs12.load_pkcs12(certdata, None)
        except (TypeError, ValueError) as e:
            raise Exception(error=f'Error in loading certificate: {str(e)}')
        self.certificate = p12.cert
        self.intermediates = p12.additional_certs
        self.private_key = p12.key

    def get_certificate(self):
        return self.certificate.certificate.public_bytes(
            encoding=serialization.Encoding.PEM).strip()

    def get_intermediates(self):
        if self.intermediates:
            int_data = [
                ic.certificate.public_bytes(
                    encoding=serialization.Encoding.PEM).strip()
                for ic in self.intermediates
            ]
            return int_data
        return None

    def get_private_key(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()).strip()

    def get_private_key_passphrase(self):
        return None


def create_temporary_cert_files(pkcs12file):
    certobj = PKCS12Cert(pkcs12file)
    cert_data = certobj.get_certificate()
    key_data = certobj.get_private_key()
    pem_certfile = tempfile.NamedTemporaryFile()
    pem_certfile.write(cert_data)
    pem_certfile.flush()
    pem_keyfile = tempfile.NamedTemporaryFile()
    pem_keyfile.write(key_data)
    pem_keyfile.flush()
    return (pem_certfile, pem_keyfile)



def create_empty_sd():
    sd = SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'
    sd['Sbz1'] = b'\x00'
    sd['Control'] = 32772
    sd['OwnerSid'] = LDAP_SID()
    # BUILTIN\Administrators
    sd['OwnerSid'].fromCanonical('S-1-5-32-544')
    sd['GroupSid'] = b''
    sd['Sacl'] = b''
    acl = ACL()
    acl['AclRevision'] = 4
    acl['Sbz1'] = 0
    acl['Sbz2'] = 0
    acl.aces = []
    sd['Dacl'] = acl
    return sd


def create_allow_ace(sid, guid_str=False):
    nace = ACE()
    nace['AceType'] = ACCESS_ALLOWED_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ACCESS_MASK()
    acedata['Mask']['Mask'] = 983551  # Full control
    acedata['Sid'] = LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    if guid_str:
        acedata['ObjectType'] = string_to_bin(guid_str)
        acedata['ObjectTypeLen'] = len(string_to_bin(guid_str))
        acedata['InheritedObjectTypeLen'] = 0
        acedata['InheritedObjectType'] = b''
    acedata['Flags'] = 1
    nace['Ace'] = acedata
    return nace



def check_ipython():
    """Returns True if script is running in interactive iPython shell"""
    try:
        get_ipython()
        return True
    except NameError:
        return False