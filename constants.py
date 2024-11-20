

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
# https://docs.microsoft.com/en-au/windows/win32/adschema/classes-all?redirectedfrom=MSDN
OBJECT_TYPES = {
    'ee914b82-0a98-11d1-adbb-00c04fd8d5cd': 'Abandon-Replication',
    '440820ad-65b4-11d1-a3da-0000f875ae0d': 'Add-GUID',
    '1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd': 'Allocate-Rids',
    '68b1d179-0d15-4d4f-ab71-46152e79a7bc': 'Allowed-To-Authenticate',
    'edacfd8f-ffb3-11d1-b41d-00a0c968f939': 'Apply-Group-Policy',
    '0e10c968-78fb-11d2-90d4-00c04f79dc55': 'Certificate-Enrollment',
    'a05b8cc2-17bc-4802-a710-e7c15ab866a2': 'Certificate-AutoEnrollment',
    '014bf69c-7b3b-11d1-85f6-08002be74fab': 'Change-Domain-Master',
    'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd': 'Change-Infrastructure-Master',
    'bae50096-4752-11d1-9052-00c04fc2d4cf': 'Change-PDC',
    'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd': 'Change-Rid-Master',
    'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd': 'Change-Schema-Master',
    'e2a36dc9-ae17-47c3-b58b-be34c55ba633': 'Create-Inbound-Forest-Trust',
    'fec364e0-0a98-11d1-adbb-00c04fd8d5cd': 'Do-Garbage-Collection',
    'ab721a52-1e2f-11d0-9819-00aa0040529b': 'Domain-Administer-Server',
    '69ae6200-7f46-11d2-b9ad-00c04f79f805': 'DS-Check-Stale-Phantoms',
    '2f16c4a5-b98e-432c-952a-cb388ba33f2e': 'DS-Execute-Intentions-Script',
    '9923a32a-3607-11d2-b9be-0000f87a36b2': 'DS-Install-Replica',
    '4ecc03fe-ffc0-4947-b630-eb672a8a9dbc': 'DS-Query-Self-Quota',
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All',
    '89e95b76-444d-4c62-991a-0facbeda640c': 'DS-Replication-Get-Changes-In-Filtered-Set',
    '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Manage-Topology',
    'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96': 'DS-Replication-Monitor-Topology',
    '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Synchronize',
    '05c74c5e-4deb-43b4-bd9f-86664c2a7fd5': 'Enable-Per-User-Reversibly-Encrypted-Password',
    'b7b1b3de-ab09-4242-9e30-9980e5d322f7': 'Generate-RSoP-Logging',
    'b7b1b3dd-ab09-4242-9e30-9980e5d322f7': 'Generate-RSoP-Planning',
    '7c0e2a7c-a419-48e4-a995-10180aad54dd': 'Manage-Optional-Features',
    'ba33815a-4f93-4c76-87f3-57574bff8109': 'Migrate-SID-History',
    'b4e60130-df3f-11d1-9c86-006008764d0e': 'msmq-Open-Connector',
    '06bd3201-df3e-11d1-9c86-006008764d0e': 'msmq-Peek',
    '4b6e08c3-df3c-11d1-9c86-006008764d0e': 'msmq-Peek-computer-Journal',
    '4b6e08c1-df3c-11d1-9c86-006008764d0e': 'msmq-Peek-Dead-Letter',
    '06bd3200-df3e-11d1-9c86-006008764d0e': 'msmq-Receive',
    '4b6e08c2-df3c-11d1-9c86-006008764d0e': 'msmq-Receive-computer-Journal',
    '4b6e08c0-df3c-11d1-9c86-006008764d0e': 'msmq-Receive-Dead-Letter',
    '06bd3203-df3e-11d1-9c86-006008764d0e': 'msmq-Receive-journal',
    '06bd3202-df3e-11d1-9c86-006008764d0e': 'msmq-Send',
    'a1990816-4298-11d1-ade2-00c04fd8d5cd': 'Open-Address-Book',
    '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2': 'Read-Only-Replication-Secret-Synchronization',
    '45ec5156-db7e-47bb-b53f-dbeb2d03c40f': 'Reanimate-Tombstones',
    '0bc1554e-0a99-11d1-adbb-00c04fd8d5cd': 'Recalculate-Hierarchy',
    '62dd28a8-7f46-11d2-b9ad-00c04f79f805': 'Recalculate-Security-Inheritance',
    'ab721a56-1e2f-11d0-9819-00aa0040529b': 'Receive-As',
    '9432c620-033c-4db7-8b58-14ef6d0bf477': 'Refresh-Group-Cache',
    '1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8': 'Reload-SSL-Certificate',
    '7726b9d5-a4b4-4288-a6b2-dce952e80a7f': 'Run-Protect_Admin_Groups-Task',
    '91d67418-0135-4acc-8d79-c08e857cfbec': 'SAM-Enumerate-Entire-Domain',
    'ab721a54-1e2f-11d0-9819-00aa0040529b': 'Send-As',
    'ab721a55-1e2f-11d0-9819-00aa0040529b': 'Send-To',
    'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501': 'Unexpire-Password',
    '280f369c-67c7-438e-ae98-1d46f3c6f541': 'Update-Password-Not-Required-Bit',
    'be2bb760-7f46-11d2-b9ad-00c04f79f805': 'Update-Schema-Cache',
    'ab721a53-1e2f-11d0-9819-00aa0040529b': 'User-Change-Password',
    '00299570-246d-11d0-a768-00aa006e0529': 'User-Force-Change-Password',
    '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e': 'DS-Clone-Domain-Controller',
    '084c93a2-620d-4879-a836-f0ae47de0e89': 'DS-Read-Partition-Secrets',
    '94825a8d-b171-4116-8146-1e34d8f54401': 'DS-Write-Partition-Secrets',
    '4125c71f-7fac-4ff0-bcb7-f09a41325286': 'DS-Set-Owner',
    '88a9933e-e5c8-4f2a-9dd7-2527416b8092': 'DS-Bypass-Quota',
    '9b026da6-0d3c-465c-8bee-5199d7165cba': 'DS-Validated-Write-Computer',
    'e362ed86-b728-0842-b27d-2dea7a9df218': 'ms-DS-ManagedPassword',
    '037088f8-0ae1-11d2-b422-00a0c968f939': 'rASInformation',
    '3e0abfd0-126a-11d0-a060-00aa006c33ed': 'sAMAccountName',
    '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79': 'msDS-AllowedToActOnBehalfOfOtherIdentity',
    '46a9b11d-60ae-405a-b7e8-ff8a58d456d2': 'tokenGroupsGlobalAndUniversal',
    '47cf3000-0019-4754-8c71-da7b9a2d5349': '47cf3000-0019-4754-8c71-da7b9a2d5349', # could not find
    '4828cc14-1437-45bc-9b07-ad6f015e5f28': 'inetOrgPerson',
    '4c164200-20c0-11d0-a768-00aa006e0529': 'userAccountRestrictions',
    '5805bc62-bdc9-4428-a5e2-856a0f4c185e': 'terminalServerLicenseServer',
    '59ba2f42-79a2-11d0-9020-00c04fc2d3cf': 'generalInformation',
    '5b47d60f-6090-40b2-9f37-2a4de88f3063': 'msDS-KeyCredentialLink',
    '5f202010-79a5-11d0-9020-00c04fc2d4cf': 'logonInformation',
    '6db69a1c-9422-11d1-aebd-0000f80367c1': 'terminalServer',
    '72e39547-7b18-11d1-adef-00c04fd8d5cd': 'validatedDNSHostName',
    '736e4812-af31-11d2-b7df-00805f48caeb': 'trustedDomain',
    '77b5b886-944a-11d1-aebd-0000f80367c1': 'personalInformation',
    '91e647de-d96f-4b70-9557-d63ff4f3ccd8': 'privateInformation',
    'b7c69e6d-2cc7-11d2-854e-00a0c983f608': 'tokenGroups',
    'b8119fd0-04f6-4762-ab7a-4986c76b3f9a': 'domainOtherParameters',
    'bc0ac240-79a9-11d0-9020-00c04fc2d4cf': 'groupMembership',
    'bf967950-0de6-11d0-a285-00aa003049e2': 'description',
    'bf967953-0de6-11d0-a285-00aa003049e2': 'displayName',
    'bf967a7f-0de6-11d0-a285-00aa003049e2': 'userCertificate',
    'bf967a86-0de6-11d0-a285-00aa003049e2': 'computer',
    'bf967a9c-0de6-11d0-a285-00aa003049e2': 'organizationalUnit',
    'bf967aa8-0de6-11d0-a285-00aa003049e2': 'printer',
    'bf967aba-0de6-11d0-a285-00aa003049e2': 'user',
    'c47d1819-529b-4c8a-8516-4f273a07e43c': 'c47d1819-529b-4c8a-8516-4f273a07e43c', # could not find
    'c7407360-20bf-11d0-a768-00aa006e0529': 'domainPassword',
    'e45795b2-9455-11d1-aebd-0000f80367c1': 'emailInformation',
    'e45795b3-9455-11d1-aebd-0000f80367c1': 'webInformation',
    'e48d0154-bcf8-11d1-8702-00c04fb96050': 'publicInformation',
    'ea1b7b93-5e48-46d5-bc6c-4df4fda78a35': 'msTPM-TpmInformationForComputer',
    'f3a64788-5306-11d1-a9c5-0000f80367c1': 'servicePrincipalName',
    'bf967aa5-0de6-11d0-a285-00aa003049e2': 'organizationalUnit',
    'bf967a9c-0de6-11d0-a285-00aa003049e2': 'group',
    '5cb41ed0-0e4c-11d0-a286-00aa003049e2': 'contact',
    '19195a5a-6da0-11d0-afd3-00c04fd930c9': 'domain',
    'f30e3bc2-9ff0-11d1-b603-0000f80367c1': 'groupPolicyContainer',
    '4c164200-20c0-11d0-a768-00aa006e0529': 'User-Account-Restrictions',
    'ea1dddc4-60ff-416e-8cc0-17cee534bce7': 'ms-PKI-Certificate-Name-Flag',
    'd15ef7d8-f226-46db-ae79-b34e560bd12c': 'ms-PKI-Enrollment-Flag',
    'e5209ca2-3bba-11d2-90cc-00c04fd91ab1': 'PKI-Certificate-Template',
    '00000000-0000-0000-0000-000000000000': 'AllProperties'
}


# well known SIDS https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
WELL_KNOWN_SIDS = {
    'S-1-0': ['Null Authority', 'User'],
    'S-1-0-0': ['Nobody', 'User'],
    'S-1-1': ['World Authority', 'User'],
    'S-1-1-0': ['Everyone', 'Group'],
    'S-1-2': ['Local Authority', 'User'],
    'S-1-2-0': ['Local', 'Group'],
    'S-1-2-1': ['Console Logon', 'Group'],
    'S-1-3': ['Creator Authority', 'User'],
    'S-1-3-0': ['Creator Owner', 'User'],
    'S-1-3-1': ['Creator Group', 'Group'],
    'S-1-3-2': ['Creator Owner Server', 'Computer'],
    'S-1-3-3': ['Creator Group Server', 'Computer'],
    'S-1-3-4': ['Owner Rights', 'Group'],
    'S-1-4': ['Non-unique Authority', 'User'],
    'S-1-5': ['NT Authority', 'User'],
    'S-1-5-1': ['Dialup', 'Group'],
    'S-1-5-2': ['Network', 'Group'],
    'S-1-5-3': ['Batch', 'Group'],
    'S-1-5-4': ['Interactive', 'Group'],
    'S-1-5-6': ['Service', 'Group'],
    'S-1-5-7': ['Anonymous', 'Group'],
    'S-1-5-8': ['Proxy', 'Group'],
    'S-1-5-9': ['Enterprise Domain Controllers', 'Group'],
    'S-1-5-10': ['Principal Self', 'User'],
    'S-1-5-11': ['Authenticated Users', 'Group'],
    'S-1-5-12': ['Restricted Code', 'Group'],
    'S-1-5-13': ['Terminal Server Users', 'Group'],
    'S-1-5-14': ['Remote Interactive Logon', 'Group'],
    'S-1-5-15': ['This Organization', 'Group'],
    'S-1-5-17': ['IUSR', 'User'],
    'S-1-5-18': ['Local System', 'User'],
    'S-1-5-19': ['NT Authority', 'User'],
    'S-1-5-20': ['Network Service', 'User'],
    'S-1-5-80-0': ['All Services ', 'Group'],
    'S-1-5-32-544': ['Administrators', 'Group'],
    'S-1-5-32-545': ['Users', 'Group'],
    'S-1-5-32-546': ['Guests', 'Group'],
    'S-1-5-32-547': ['Power Users', 'Group'],
    'S-1-5-32-548': ['Account Operators', 'Group'],
    'S-1-5-32-549': ['Server Operators', 'Group'],
    'S-1-5-32-550': ['Print Operators', 'Group'],
    'S-1-5-32-551': ['Backup Operators', 'Group'],
    'S-1-5-32-552': ['Replicators', 'Group'],
    'S-1-5-32-554': ['Pre-Windows 2000 Compatible Access', 'Group'],
    'S-1-5-32-555': ['Remote Desktop Users', 'Group'],
    'S-1-5-32-556': ['Network ConfiguratiManagedServiceAccountn Operators', 'Group'],
    'S-1-5-32-557': ['Incoming Forest Trust Builders', 'Group'],
    'S-1-5-32-558': ['Performance Monitor Users', 'Group'],
    'S-1-5-32-559': ['Performance Log Users', 'Group'],
    'S-1-5-32-560': ['Windows Authorization Access Group', 'Group'],
    'S-1-5-32-561': ['Terminal Server License Servers', 'Group'],
    'S-1-5-32-562': ['Distributed COM Users', 'Group'],
    'S-1-5-32-568': ['IIS_IUSRS', 'Group'],
    'S-1-5-32-569': ['Cryptographic Operators', 'Group'],
    'S-1-5-32-573': ['Event Log Readers', 'Group'],
    'S-1-5-32-574': ['Certificate Service DCOM Access', 'Group'],
    'S-1-5-32-575': ['RDS Remote Access Servers', 'Group'],
    'S-1-5-32-576': ['RDS Endpoint Servers', 'Group'],
    'S-1-5-32-577': ['RDS Management Servers', 'Group'],
    'S-1-5-32-578': ['Hyper-V Administrators', 'Group'],
    'S-1-5-32-579': ['Access Control Assistance Operators', 'Group'],
    'S-1-5-32-580': ['Remote Management Users', 'Group'],
    'S-1-5-32-581': ['Default Account', 'Group'],
    'S-1-5-32-582': ['Storage Replica Administrators', 'Group'],
    'S-1-5-32-583': ['Device Owners', 'Group']
}


#https://learn.microsoft.com/en-us/windows/win32/adschema/a-samaccounttype
SAMACCOUNTTYPES = {
    'SAM_DOMAIN_OBJECT' : 0x0,
    'SAM_GROUP_OBJECT' : 0x10000000,
    'SAM_NON_SECURITY_GROUP_OBJECT' : 0x10000001,
    'SAM_ALIAS_OBJECT' : 0x20000000,
    'SAM_NON_SECURITY_ALIAS_OBJECT' : 0x20000001,
    'SAM_USER_OBJECT' : 0x30000000,
    'SAM_NORMAL_USER_ACCOUNT' : 0x30000000,
    'SAM_MACHINE_ACCOUNT' : 0x30000001,
    'SAM_TRUST_ACCOUNT' :  0x30000002,
    'SAM_APP_BASIC_GROUP' :  0x40000000,
    'SAM_APP_QUERY_GROUP' :  0x40000001,
    'SAM_ACCOUNT_TYPE_MAX' : 0x7fffffff
}


# used for automated flag parsing for field parsing based on LDAP entry field name
FLAGS = {

    #https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
    'userAccountControl' : 
    {
        'SCRIPT'            : 0x0001,
        'ACCOUNTDISABLE'    : 0x0002,
        'HOMEDIR_REQUIRED'  : 0x0008,
        'LOCKOUT'           : 0x0010,
        'PASSWD_NOTREQD'    : 0x0020,
        'PASSWD_CANT_CHANGE': 0x0040,
        'ENCRYPTED_TEXT_PWD_ALLOWED' : 	0x0080,
        'TEMP_DUPLICATE_ACCOUNT' : 	0x0100,
        'NORMAL_ACCOUNT' : 	0x0200,
        'INTERDOMAIN_TRUST_ACCOUNT' : 0x0800,
        'WORKSTATION_TRUST_ACCOUNT' : 0x1000,
        'SERVER_TRUST_ACCOUNT' : 0x2000,
        'DONT_EXPIRE_PASSWORD' : 0x10000,
        'MNS_LOGON_ACCOUNT' : 0x20000,
        'SMARTCARD_REQUIRED' : 0x40000,
        'TRUSTED_FOR_DELEGATION' : 0x80000,
        'NOT_DELEGATED'	: 0x100000,
        'USE_DES_KEY_ONLY' : 0x200000,
        'DONT_REQ_PREAUTH': 0x400000,
        'PASSWORD_EXPIRED' : 0x800000,
        'TRUSTED_TO_AUTH_FOR_DELEGATION' :0x1000000,
        'PARTIAL_SECRETS_ACCOUNT': 0x04000000,
    },

    #https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c
    'trustAttributes' :
    {
        'NON_TRANSITIVE':0x00000001,
        'UPLEVEL_ONLY':0x00000002,
        'QUARANTINED_DOMAIN':0x00000004,
        'FOREST_TRANSITIVE':0x00000008,
        'CROSS_ORGANIZATION':0x00000010,
        'WITHIN_FOREST':0x00000020,
        'TREAT_AS_EXTERNAL':0x00000040,
        'USES_RC4_ENCRYPTION':0x00000080,
        'CROSS_ORGANIZATION_NO_TGT_DELEGATION':0x00000200,
        'CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION': 0x00000800,
        'PIM_TRUST':0x00000400
    },

    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1
    'msPKI-Certificate-Name-Flag': 
    {
        'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT': 0x00000001,
        'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME': 0x00010000,
        'CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS': 0x00400000,
        'CT_FLAG_SUBJECT_ALT_REQUIRE_SPN': 0x00800000,
        'CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID': 0x01000000,
        'CT_FLAG_SUBJECT_ALT_REQUIRE_UPN': 0x02000000,
        'CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL': 0x04000000, 
        'CT_FLAG_SUBJECT_ALT_REQUIRE_DNS': 0x08000000, 
        'CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN': 0x10000000, 
        'CT_FLAG_SUBJECT_REQUIRE_EMAIL': 0x20000000, 
        'CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME': 0x40000000, 
        'CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH': 0x80000000,
        'CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME': 0x00000008
    },

    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1
    'msPKI-Enrollment-Flag': {
        'CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS': 0x00000001, 
        'CT_FLAG_PEND_ALL_REQUESTS': 0x00000002, 
        'CT_FLAG_PUBLISH_TO_KRA_CONTAINER': 0x00000004, 
        'CT_FLAG_PUBLISH_TO_DS': 0x00000008,
        'CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE': 0x00000010,
        'CT_FLAG_AUTO_ENROLLMENT': 0x00000020,
        'CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT': 0x00000040,
        'CT_FLAG_USER_INTERACTION_REQUIRED': 0x00000100,
        'CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE': 0x00000400,
        'CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF': 0x00000800,
        'CT_FLAG_ADD_OCSP_NOCHECK': 0x00001000,
        'CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL': 0x00002000,
        'CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS': 0x00004000,
        'CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS': 0x00008000,
        'CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT': 0x00010000,
        'CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST': 0x00020000,
        'CT_FLAG_SKIP_AUTO_RENEWAL': 0x00040000,
        'CT_FLAG_NO_SECURITY_EXTENSION': 0x00080000
    }, 

    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/f6122d87-b999-4b92-bff8-f465e8949667
    # FEATURE: Extra processing can be done on the marked entries as per above
    'msPKI-Private-Key-Flag': {
        'CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL': 0x00000001,
        'CT_FLAG_EXPORTABLE_KEY': 0x00000010,
        'CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED': 0x00000020,
        'CT_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM': 0x00000040,
        'CT_FLAG_REQUIRE_SAME_KEY_RENEWAL': 0x00000080,
        'CT_FLAG_USE_LEGACY_PROVIDER': 0x00000100,
        'CT_FLAG_ATTEST_NONE': 0x00000000, # * 
        'CT_FLAG_ATTEST_REQUIRED': 0x00002000, # *
        'CT_FLAG_ATTEST_PREFERRED': 0x00001000, # *
        'CT_FLAG_ATTESTATION_WITHOUT_POLICY': 0x00004000, # *
        'CT_FLAG_EK_TRUST_ON_USE': 0x00000200, # *
        'CT_FLAG_EK_VALIDATE_CERT': 0x00000400, # *
        'CT_FLAG_EK_VALIDATE_KEY': 0x00000800, # *
        'CT_FLAG_HELLO_LOGON_KEY': 0x00200000 # *
    },

}


# used for automated lookups for field parsing based on LDAP entry field name
LOOKUPS = {
    #https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5026a939-44ba-47b2-99cf-386a9e674b04
    'trustDirection' : {0 : 'DISABLED', 1: 'INBOUND', 2: 'OUTBOUND', 3: 'BIDIRECTIONAL'},
    
    #https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/36565693-b5e4-4f37-b0a8-c1b12138e18e
    'trustType' : {1 : 'DOWNLEVEL', 2: 'UPLEVEL', 3: 'MIT', 4: 'DCE', 5: 'AAD'}
}

# default app cert policies
DEFAULT_KEY_USAGE = [
    'CLIENT_AUTH',
    'EMAIL_PROTECTION',
    'EFS_CRYPTO'
]

DEFAULT_SMIME_CAPABILITIES = [
    ['1.2.840.113549.3.2', 128],
    ['1.2.840.113549.3.4', 128],
    ['1.3.14.3.2.7'], 
    ['1.2.840.113549.3.7']
]


MS_OIDS = {
    'RC2_CBC': '1.2.840.113549.3.2',
    'RC4': '1.2.840.113549.3.4',
    'DES_CBC': '1.3.14.3.2.7',
    'DES_EDE3_CBC': '1.2.840.113549.3.7',
    'microsoftCaVersion' : '1.3.6.1.4.1.311.21.1',
    'EFS_CRYPTO': '1.3.6.1.4.1.311.10.3.4',
    'APPLICATION_CERT_POLICIES': '1.3.6.1.4.1.311.21.10',
    'sMIMECapabilities': '1.2.840.113549.1.9.15',
    'NT_PRINCIPAL_NAME': '1.3.6.1.4.1.311.20.2.3',
    'NT_PRINCIPAL_SID': '1.3.6.1.4.1.311.25.2',
    'NTDS_CA_SECURITY_EXT': '1.3.6.1.4.1.311.25.2.1',

}

