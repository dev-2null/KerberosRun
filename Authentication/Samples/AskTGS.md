```powershell
PS C:\Users> .\KerberosRun.exe --asktgs --user normaluser --pass [...] --spn time/win10.corplab.local --verbose --decrypttgs [...] --decryptetype aes256 --srvname adminuser

   __           __
  / /_____ ____/ /  ___ _______  ___ ______ _____
 /  '_/ -_) __/ _ \/ -_) __/ _ \(_-</ __/ // / _ \
/_/\_\\__/_/ /_.__/\__/_/  \___/___/_/  \_,_/_//_/

  v1.0.0
[*] Starting Kerberos Authentication ...
[*] Sending AS-REQ ...
    * MessageType :  KRB_AS_REQ
    * pvno :  5
    * PaData :
       - PA_PAC_REQUEST :
          - IncludePac :  True
    * Body :
       - KdcOptions :  RenewableOk, Canonicalize, Renewable, Forwardable
       - CName :
          - Type :  NT_PRINCIPAL
          - Name :  normaluser
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_SRV_INST
          - Name :  krbtgt
          - Name :  CORPLAB.LOCAL
       - Till :  9/13/2037 2:48:05 AM +00:00
       - RTime :  9/13/2037 2:48:05 AM +00:00
       - Nonce :  637261653
       - EType :
          - EncType :  AES256_CTS_HMAC_SHA1_96
          - EncType :  AES128_CTS_HMAC_SHA1_96
          - EncType :  RC4_HMAC_NT
          - EncType :  RC4_HMAC_NT_EXP
          - EncType :  RC4_HMAC_OLD_EXP
       - Addresses :
          - Type :  NetBios
          - Addresses :  ADMINSTAT
       - AdditionalTickets :
       - EncAuthorizationData :
       - From :
[*] Sending AS-REQ ...
    * MessageType :  KRB_AS_REQ
    * pvno :  5
    * PaData :
       - PA_PAC_REQUEST :
          - IncludePac :  True
    * Body :
       - KdcOptions :  RenewableOk, Canonicalize, Renewable, Forwardable
       - CName :
          - Type :  NT_PRINCIPAL
          - Name :  normaluser
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_SRV_INST
          - Name :  krbtgt
          - Name :  CORPLAB.LOCAL
       - Till :  9/13/2037 2:48:05 AM +00:00
       - RTime :  9/13/2037 2:48:05 AM +00:00
       - Nonce :  637261654
       - EType :
          - EncType :  AES256_CTS_HMAC_SHA1_96
          - EncType :  AES128_CTS_HMAC_SHA1_96
          - EncType :  RC4_HMAC_NT
          - EncType :  RC4_HMAC_NT_EXP
          - EncType :  RC4_HMAC_OLD_EXP
       - Addresses :
          - Type :  NetBios
          - Addresses :  ADMINSTAT
       - AdditionalTickets :
       - EncAuthorizationData :
       - From :
[*] Receiving AS-REP...
    * MessageType :  KRB_AS_REP
    * pvno :  5
    * PaData :
       - PA_ETYPE_INFO2 :
          - EType :  AES256_CTS_HMAC_SHA1_96
          - S2kParams :
          - Salt :  CORPLAB.LOCALnormaluser
    * CRealm :  CORPLAB.LOCAL
    * CName :
       - Type :  NT_PRINCIPAL
       - Name :  normaluser
    * Ticket :
       - tkt-vno :  5
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Name :  krbtgt
          - Type :  NT_SRV_INST
       - EncryptedPart :
          - kvno :  11
          - EType :  AES256_CTS_HMAC_SHA1_96
          - Cipher :  [krbtgtEncryptedCipher...]
    * Enc-Part :
       - kvno :  6
       - EType :  AES256_CTS_HMAC_SHA1_96
       - Cipher :  [ClientEncryptedCipher...]
[+] TGT Kirbi:
    - doIFHDCCBRigAwIBBaEDAgEWooIEHDCCBBhhggQUMIIEEKADAgEFoQ8bDUNPUlBMQUIuTE9DQUyiIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDUNPUlBMQUIuTE9DQUyjggPSMIIDzqADAgESoQMCAQuiggPABIIDvG9wWD+OtdyeCC9I4lqm6NMpC0TzTujqRNM60OHw51mlP6tl1yiWS26gJ+ckwTghD6OP7wWcRff8XrIQi303d4BIpO3+asp29Zk1may9VKMUwqNPoFov9zc8eO7M6OTQxH6gBY4aLNd2y/livA55wFW3E+gBWMzvQ5ctKsyhzecAT3XOjH5uURHGTaA+4OwEoCyvKfywy10qhEfR5uo0S4pXWq2spp9DmlrPn+qXoeAtAHkgc4ugsWhsWF96aUoy0ZgpyPrH6afRo30kN5+EO/029ie+HcuuXvBzoFCiDVfuNQHlnpBeg5XOfr5h9KSwBdBXGQq+aGoJV/Rc4++FrUvjpDI9+4E3m90dH87pevnCAFHrU1l+YSF0BgFumIhUadasAVs1ELp1kJ6p08yd8qZOb/fw2m09Ru+ToMxp0xlh++/IkakqqoADDilxrCnhUZtCfnppKuAwoggPupIZGro3J0YV8beEioArRfHr5fZWBv/o2s4idA/Qn4kogb/uQmb4HIVqi/6nXXKmpO3UxE7qtWQteSGb+VCRaFHkdWsNbEm8OXkU74GJtRKc/iD2QkpB0mdl9cl38yvu7e5+cCSw2wXr2DcAHiLzay/MNbP+kuaspjpbVFz6YunNDzV7QUfuwaeMPsakCHTuQ1qGKfnayCNTvTuwLhY3ROXqED2yXB6CflxKWS1RogUUKMheNuVCTUvXkuEehn8fcBJOcLp/XApJSj704b4J8W2YJ3QZJsFuVsBGXI8IodzRmNGvw3BMNSl3dWBpP4ur2hLUBGAxhyFiElc7Da1hNHQdGan7Rcl/DKPhdvrTVTpmCoOEPVhWbJKptrqgSe3tmquZloSyu28//JqSF/58lKx2Hxyp9L/hpovsbuJaucvmeUkJciT6mBKHvk0+c4OrPHSyrrNP/fsJo4IHRBMtVXiP2WEJKrsYkTxYZ5kB39i9SxnIxhDoREd9d5bz0kZ6zET6lF7D54NbaHv8Y6izRzyt2JlRbR2uXVzTMtOr3LoOu3UJW0yf7batnf6ZQSKSDE4ez7gfEBZXDHhFhFkiae08/cgIk/qZd3Ijr3SkhSaaktXbTqeLI4r9URbcY7N1phFJOzmy4CuGk2X8gFBepY21F7s9UQJCHqjRzlqEOlPspYf6UxurgcIRq10KuS7WTZAY1debbiI/7NRQ2G+heeqmmOrrGyTAKWpvJVPRZWiZzO6MzuKYgOBgSmq8twiSxNoL/R019h/qpus48gQzOQpchBjGQ6WJT/ReJFD6VGVlo4HrMIHooAMCAQCigeAEgd19gdowgdeggdQwgdEwgc6gKzApoAMCARKhIgQgzkMboQVwYSHS19ZADYZ32x1nJh6ubF1OlC++rN/9hU2hDxsNQ09SUExBQi5MT0NBTKIXMBWgAwIBAaEOMAwbCm5vcm1hbHVzZXKjBwMFAEDBAAClERgPMjAyMDA1MjcwODM0MTJaphEYDzIwMjAwNTI3MTgzNDEyWqcRGA8yMDIwMDYwMzA4MzQxMlqoDxsNQ09SUExBQi5MT0NBTKkiMCCgAwIBAqEZMBcbBmtyYnRndBsNQ09SUExBQi5MT0NBTA==
[*] Sending TGS-REQ ...
    * MessageType :  KRB_TGS_REQ
    * pvno :  5
    * PaData :
       - PA_TGS_REQ :
          - KRB_AP_REQ :
             - pvno :  5
             - ApOptions :  Reserved
             - Ticket :
                - tkt-vno :  5
                - Realm :  CORPLAB.LOCAL
                - SName :
                   - Type :  NT_SRV_INST
                   - Name :  krbtgt
                   - Name :  CORPLAB.LOCAL
                - EncryptedPart :
                   - kvno :  11
                   - EType :  AES256_CTS_HMAC_SHA1_96
                   - Cipher :  [krbtgtEncryptedCipher...]
             - Authenticator :
                - kvno :
                - EType :  AES256_CTS_HMAC_SHA1_96
                - Realm :  CORPLAB.LOCAL
                - SequenceNumber :  637261656
                - Subkey :
                   - EType :  AES256_CTS_HMAC_SHA1_96
                   - KeyValue :  23E8CB62AD98396C032A76845F3EEC24EA828082CC98F76D4B0E0947C10DE85E
                - CTime :  5/27/2020 8:34:12 AM +00:00
                - CuSec :  810
                - CName :
                   - Type :  NT_PRINCIPAL
                   - Name :  normaluser
                - Checksum :
                   - Type :  HMAC_SHA1_96_AES256
                   - Checksum :  D8389B6B07E8793C11B7FEC3
                - AuthorizationData :
                - AuthenticatorVersionNumber :  5
       - PA_PAC_OPTIONS :
          - Flags :  BranchAware
    * Body :
       - KdcOptions :  RenewableOk, Canonicalize, Renewable, Forwardable
       - Realm :  corplab.local
       - SName :
          - Type :  NT_SRV_INST
          - Name :  time
          - Name :  win10.corplab.local
       - Till :  9/13/2037 2:48:05 AM +00:00
       - RTime :
       - Nonce :  637261655
       - EType :
          - EncType :  RC4_HMAC_NT
       - EncAuthorizationData :
       - From :
       - AdditionalTickets :
[*] Receiving TGS-REP ...
    * MessageType :  KRB_TGS_REP
    * pvno :  5
    * PaData :
    * CRealm :  CORPLAB.LOCAL
    * CName :
       - Type :  NT_PRINCIPAL
       - Name :  normaluser
    * Ticket :
       - tkt-vno :  5
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Name :  time
          - Type :  NT_SRV_INST
       - EncryptedPart :
          - kvno :  5
          - EType :  AES256_CTS_HMAC_SHA1_96
          - Cipher :  [ServiceEncryptedCipher...]
    * Enc-Part :
       - EType :  AES256_CTS_HMAC_SHA1_96
       - kvno :
       - Cipher :  [SubSessionKeyEncryptedCipher..]
    * [Decrypted Enc-Part]:
       - AuthTime :  5/27/2020 8:34:12 AM +00:00
       - StartTime :  5/27/2020 8:34:12 AM +00:00
       - EndTime :  5/27/2020 6:34:12 PM +00:00
       - RenewTill :  6/3/2020 8:34:12 AM +00:00
       - Nonce :  637261655
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_SRV_INST
          - Name :  time
          - Name :  win10.corplab.local
       - EncryptedPaData :
          - PA_SUPPORTED_ETYPES :
             - Value : 1F000000
          - PA_PAC_OPTIONS :
             - Flags :  BranchAware
       - Key :
          - EType :  RC4_HMAC_NT
          - Value :  4C76CFB5C06C436BD30E203D00C5CAEF
       - KeyExpiration :
       - Flags :  EncryptedPreAuthentication, Renewable, Forwardable
       - LastReq
          - Type :  0
          - Type :  5/27/2020 8:34:12 AM +00:00
    * [Decrypted Ticket Enc-Part]:
       - AuthTime :  5/27/2020 8:34:12 AM +00:00
       - StartTime :  5/27/2020 8:34:12 AM +00:00
       - EndTime :  5/27/2020 6:34:12 PM +00:00
       - RenewTill :  6/3/2020 8:34:12 AM +00:00
       - CRealm :  CORPLAB.LOCAL
       - CName :
          - Type :  NT_PRINCIPAL
          - Name :  normaluser
       - AuthorizationData :
          - Type :  AdIfRelevant
             - Type :  AdWin2kPac
                - Type :  AdWin2kPac
                - Version :  0
                - LogonInfo :
                   - PacType :
                   - DomainId :
                      - Revision :  1
                      - IdentifierAuthority :  NTAuthority
                      - SubAuthority :  21, 1977317821, 1772133574, 954835042
                      - SubAuthorityCount :  4
                   - ExtraIds :
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
                      - Sid :  S-1-18-1
                      - Revision :  1
                      - IdentifierAuthority :  AuthenticationAuthority
                      - SubAuthority :  1
                      - SubAuthorityCount :  1
                   - DomainSid :
                      - Attributes :  0
                      - Id :  954835042
                      - Value :  S-1-5-21-1977317821-1772133574-954835042
                   - ExtraSidCount :  1
                   - ExtraSids :
                      - Id :  1
                      - Attributes :  0
                      - Value :  S-1-18-1
                   - GroupCount :  1
                   - GroupId :  513
                   - GroupIds :
                      - RelativeId :  513
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
                   - GroupSid :  S-1-5-21-1977317821-1772133574-954835042-513
                   - GroupSids :
                      - Id :  513
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
                      - Value :  S-1-5-21-1977317821-1772133574-954835042-513
                   - HomeDirectory :
                   - HomeDrive :
                   - KickOffTime :  1/1/0001 12:00:00 AM +00:00
                   - LastFailedILogon :  1/1/1601 12:00:00 AM +00:00
                   - LastSuccessfulILogon :  1/1/1601 12:00:00 AM +00:00
                   - LogoffTime :  1/1/0001 12:00:00 AM +00:00
                   - LogonCount :  397
                   - LogonScript :
                   - LogonTime :  5/27/2020 8:34:12 AM +00:00
                   - ProfilePath :
                   - PwdCanChangeTime :  5/1/2020 3:58:59 AM +00:00
                   - PwdLastChangeTime :  4/30/2020 3:58:59 AM +00:00
                   - PwdMustChangeTime :  1/1/0001 12:00:00 AM +00:00
                   - Reserved1 :  0, 0
                   - Reserved3 :  0
                   - ResourceDomainId :
                   - ResourceDomainSid :
                   - ResourceGroupCount :  0
                   - ResourceGroupIds :
                   - ResourceGroups :
                   - SubAuthStatus :  0
                   - UserAccountControl :  ADS_UF_LOCKOUT, ADS_UF_DONT_EXPIRE_PASSWD
                   - UserDisplayName :
                   - UserFlags :  LOGON_EXTRA_SIDS
                   - UserId :  1607
                   - UserName :  normaluser
                   - UserSessionKey :  00000000000000000000000000000000
                   - UserSid :  S-1-5-21-1977317821-1772133574-954835042-1607
                   - DomainName :  CORP
                   - ServerName :  DC1
                   - BadPasswordCount :  0
                   - FailedILogonCount :  0
                - ClientInformation :
                   - PacType :  CLIENT_NAME_TICKET_INFO
                   - ClientId :  5/27/2020 8:34:12 AM +00:00
                   - Name :  normaluser
                   - NameLength :  20
                - KdcSignature :
                   - PacType :  0
                   - RODCIdentifier :  0
                   - Signature :  3945EBABAECF5A1D97FBA860
                   - SignatureData :  [...]
                   - Type :  HMAC_SHA1_96_AES256
                   - Validated :  False
                   - Validator :
                      - Validator :  PaForUserChecksum
                      - Validator :  3945EBABAECF5A1D97FBA860
                - ServerSignature :
                   - PacType :  0
                   - RODCIdentifier :  0
                   - Signature :  5E71809C20696561C147D5DD
                   - SignatureData :  [...]
                   - Type :  HMAC_SHA1_96_AES256
                   - Validated :  False
                   - Validator :
                      - Validator :  PaForUserChecksum
                      - Validator :  5E71809C20696561C147D5DD
                - UpnDomainInformation :
                   - PacType :  UPN_DOMAIN_INFO
                   - Upn :  normaluser@corplab.local
                   - UpnLength :  48
                   - UpnOffset :  16
                   - Domain :  CORPLAB.LOCAL
                   - DnsDomainNameLength :  26
                   - DnsDomainNameOffset :  64
                - DecodingErrors :
                - HasRequiredFields :  True
       - CAddr :
       - Flags :  EncryptedPreAuthentication, Renewable, Forwardable
       - Key :
          - EType :  RC4_HMAC_NT
          - Value :  4C76CFB5C06C436BD30E203D00C5CAEF
       - Transited :
          - Type :  DomainX500Compress
          - Contents :
[+] TGS Kirbi:
    - doIFBDCCBQCgAwIBBaEDAgEWooIEEDCCBAxhggQIMIIEBKADAgEFoQ8bDUNPUlBMQUIuTE9DQUyiJjAkoAMCAQKhHTAbGwR0aW1lGxN3aW4xMC5jb3JwbGFiLmxvY2Fso4IDwjCCA76gAwIBEqEDAgEFooIDsASCA6wylVGOtQXK+t94IKXAaKeuN00l5M6bjit7CU9QDCnH6kBOYrpQljKvbnpX+E2MbkAJoV2BXjES7Xs/pPdYGkbuzyYckgF+cbsmRpd6z0vV82Aavl71mqoN9nDHG+jPFKtNe5iFC8Alri3cAJsEd/aO2m8w5U7T52bdUAH4mYp5pgAue2LFUOvY/s6TTe7l3xlR+tT4nhaYYaBafuV2lCAD8V75G8DZqixGg/rUyvRf0B50aphnaXOq7/E9oFug9zV7eQWbzXAsmdrCUkjgUJ337aW38YAUp3lDiBud4j+sZWknCqxN5dtEz0txVVBanvqrb8QphB7Gtpwz+DH2tpN9lohiesCjFxVL2uecN5vGmnnAzhROFH5PsVMrk5CPBlPviIDlZwaobzVxDU74jv/uo3l0AcsB4GvUpKw6zBR9DblRN23Apkor3muq0Xb4JKBrRwzsAeDOuI9zdueaziQZEdnaVw4TQHeglECVzEV4zjkC7WLT6OzsFNe1442E4FguHMB0o0zsyAj618kAIcDBxGplZaocOCC0FJnmdd5aB+r6yMloZFgS1RpZm0LDhT2g4e2iiZC1u4Co+J7cnuYqFUk4yIFfqJ3XEOj/fpE37rPybL1ZwOen+qf1iLoOlMDt7jqzBzl/xN3BBIozuavkk1WkIDd/tE9aE7s5bM2hramrtBwX77TNd55/QnLBKXcI1pVKgs/bsald/0+O3ji6XAB1N2dAsAQ8RH/3xrfWEEcac+NECu+6fWqGsLLsRleIY7ftbNtZaBEXR4FlO6uScH5tujnzKprp8rrcOLWYXXbxl9MqJV0khX0p19+dCbMNmjVCiNXQQahxpcj95dXzXqzfqgY6bzkiacdBjLUQOP9zS/seu9e4QC9DM81MYd5WrMk7QH8DSh36aqyBKwQmkdITr9cM/NPb7rvKQEsbP+C4H0xfSepW0n+8sY2ai3jR9xpJtgtN0YQiMFi1KgZbKBAuoRDmjpc5h3vIPAQMJq/Qwk2GbSJT8qXFMgA1lhXs8cQaevmrvqVqNzIW/7ttQKAj6UPY2iAXjVpU2uD1otDv3HE2FLYFoP9w9q1UoUWyiWxi4iNcDy2Q9yKd7N1qbaIL+WdaZV7BwtvkpK4kAKMcbFVgAEVu8wjRB9OI1xYNSrlytrqvVQXa3HpkJ9RM/ufzzb05EEADjK2tKpe9ngbr8lT1lNVeP4fsAOV5CJ9GCuWyU5T5aKTB1LCmEasqrNuwxpgMt0gJFx2Wo4HfMIHcoAMCAQCigdQEgdF9gc4wgcuggcgwgcUwgcKgGzAZoAMCARehEgQQTHbPtcBsQ2vTDiA9AMXK76EPGw1DT1JQTEFCLkxPQ0FMohcwFaADAgEBoQ4wDBsKbm9ybWFsdXNlcqMHAwUAQIEAAKURGA8yMDIwMDUyNzA4MzQxMlqmERgPMjAyMDA1MjcxODM0MTJapxEYDzIwMjAwNjAzMDgzNDEyWqgPGw1DT1JQTEFCLkxPQ0FMqSYwJKADAgECoR0wGxsEdGltZRsTd2luMTAuY29ycGxhYi5sb2NhbA==

```