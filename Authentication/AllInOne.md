```
[*] Starting Kerberos Authentication...
[*] Sending AS-REQ ...
[-] Kerberos Error: KDC KDC_ERR_PREAUTH_REQUIRED: Additional pre-authentication required
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
          - PaTimestamp :  4/13/2020 9:02:40 AM +00:00
          - PaUSec :  33181
    * Body :
       - KdcOptions :  RenewableOk, Canonicalize, Renewable, Forwardable
       - CName :
          - Type :  NT_ENTERPRISE
          - Name :  spnuseraes@CORPLAB.LOCAL
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_SRV_INST
          - Name :  krbtgt
          - Name :  CORPLAB.LOCAL
       - Till :  9/13/2037 2:48:05 AM +00:00
       - RTime :  9/13/2037 2:48:05 AM +00:00
       - Nonce :  637223655
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
          - kvno :  5
          - EType :  AES256_CTS_HMAC_SHA1_96
          - Cipher :  [krbtgtEncryptedCipher...]
    * Enc-Part :
       - kvno :  3
       - EType :  AES256_CTS_HMAC_SHA1_96
       - Cipher :  [ClientEncryptedCipher...]
    * [Decrypted Enc-Part]:
       - AuthTime :  4/13/2020 9:02:40 AM +00:00
       - StartTime :  4/13/2020 9:02:40 AM +00:00
       - EndTime :  4/13/2020 7:02:40 PM +00:00
       - RenewTill :  4/20/2020 9:02:40 AM +00:00
       - Nonce :  637223655
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
          - Value :  B120492897BF34FE489D8266959340571617A6A85728597639E0C7D9E2E299C1
       - KeyExpiration :  9/14/2037 2:48:05 AM +00:00
       - CAddr :
          - Type :  NetBios
          - Addresses :  ADMINSTAT       
       - Flags :  EncryptedPreAuthentication, PreAuthenticated, Initial, Renewable, Forwardable
       - LastReq 
          - Type :  0
          - Type :  4/13/2020 9:02:40 AM +00:00

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
                   - kvno :  5
                   - EType :  AES256_CTS_HMAC_SHA1_96
                   - Cipher :  [krbtgtEncryptedCipher...]
             - Authenticator : 
                - kvno :  
                - EType :  AES256_CTS_HMAC_SHA1_96
                - Realm :  CORPLAB.LOCAL
                - SequenceNumber :  637223657
                - Subkey :
                   - EType :  AES256_CTS_HMAC_SHA1_96
                   - KeyValue :  6E9F13612E3D38A16E4096E02DAC0B97219292BB877A123DA37EDC9ECBDCA56D
                - CTime :  4/13/2020 9:02:40 AM +00:00
                - CuSec :  826
                - CName :  
                   - Type :  NT_PRINCIPAL
                   - Name :  spnuseraes
                - Checksum :
                   - Type :  HMAC_SHA1_96_AES256
                   - Checksum :  180DD5F20A995A18A44C5419
                - AuthorizationData :  
                - AuthenticatorVersionNumber :  5
       - PA_PAC_OPTIONS :
          - Flags :  BranchAware
    * Body :
       - KdcOptions :  RenewableOk, Canonicalize, Renewable, Forwardable
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_SRV_INST
          - Name :  unconstrained
          - Name :  adminstat.corplab.local
       - Till :  9/13/2037 2:48:05 AM +00:00
       - RTime :  
       - Nonce :  637223656
       - EType :
          - EncType :  AES256_CTS_HMAC_SHA1_96
          - EncType :  AES128_CTS_HMAC_SHA1_96
          - EncType :  RC4_HMAC_NT
          - EncType :  RC4_HMAC_NT_EXP
          - EncType :  RC4_HMAC_OLD_EXP
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
       - Name :  spnuseraes
    * Ticket :
       - tkt-vno :  5
       - Realm :  CORPLAB.LOCAL
       - SName : 
          - Name :  unconstrained
          - Type :  NT_SRV_INST
       - EncryptedPart :
          - kvno :  2
          - EType :  RC4_HMAC_NT
          - Cipher :  [ServiceEncryptedCipher...]
    * Enc-Part :
       - EType :  AES256_CTS_HMAC_SHA1_96
       - kvno :  
       - Cipher :  [SubSessionKeyEncryptedCipher..]
    * [Decrypted Enc-Part]:
       - AuthTime :  4/13/2020 9:02:40 AM +00:00
       - StartTime :  4/13/2020 9:02:40 AM +00:00
       - EndTime :  4/13/2020 7:02:40 PM +00:00
       - RenewTill :  4/20/2020 9:02:40 AM +00:00
       - Nonce :  637223656
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_SRV_INST
          - Name :  unconstrained
          - Name :  adminstat.corplab.local
       - EncryptedPaData :
          - PA_SUPPORTED_ETYPES :
             - Value : 07000000
          - PA_PAC_OPTIONS :
             - Flags :  BranchAware
       - Key :
          - EType :  RC4_HMAC_NT
          - Value :  F7EB00C8784F11D1870E1D0998EE742F
       - KeyExpiration :  
       - Flags :  EncryptedPreAuthentication, OkAsDelegate, PreAuthenticated, Renewable, Forwardable
       - LastReq 
          - Type :  0
          - Type :  4/13/2020 9:02:40 AM +00:00

[*] Target Server is Trusted For Delegation, asking Forwarded TGT...

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
                   - kvno :  5
                   - EType :  AES256_CTS_HMAC_SHA1_96
                   - Cipher :  [krbtgtEncryptedCipher...]
             - Authenticator : 
                - kvno :  
                - EType :  AES256_CTS_HMAC_SHA1_96
                - Realm :  CORPLAB.LOCAL
                - SequenceNumber :  637223659
                - Subkey :
                   - EType :  AES256_CTS_HMAC_SHA1_96
                   - KeyValue :  1ABDD38F553AE5C220F5C09A9D2C916F28EA1E0393AE5DA29DA62667FA9D16DB
                - CTime :  4/13/2020 9:02:40 AM +00:00
                - CuSec :  882
                - CName :  
                   - Type :  NT_PRINCIPAL
                   - Name :  spnuseraes
                - Checksum :
                   - Type :  HMAC_SHA1_96_AES256
                   - Checksum :  33E4F23D667FCD31B27DFFF5
                - AuthorizationData :  
                - AuthenticatorVersionNumber :  5
       - PA_PAC_OPTIONS :
          - Flags :  BranchAware
    * Body :
       - KdcOptions :  RenewableOk, Canonicalize, Renewable, Forwarded, Forwardable
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_SRV_INST
          - Name :  krbtgt
          - Name :  CORPLAB.LOCAL
       - Till :  9/13/2037 2:48:05 AM +00:00
       - RTime :  
       - Nonce :  637223658
       - EType :
          - EncType :  AES256_CTS_HMAC_SHA1_96
          - EncType :  AES128_CTS_HMAC_SHA1_96
          - EncType :  RC4_HMAC_NT
          - EncType :  RC4_HMAC_NT_EXP
          - EncType :  RC4_HMAC_OLD_EXP
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
       - Name :  spnuseraes
    * Ticket :
       - tkt-vno :  5
       - Realm :  CORPLAB.LOCAL
       - SName : 
          - Name :  krbtgt
          - Type :  NT_SRV_INST
       - EncryptedPart :
          - kvno :  5
          - EType :  AES256_CTS_HMAC_SHA1_96
          - Cipher :  [krbtgtEncryptedCipher...]
    * Enc-Part :
       - EType :  AES256_CTS_HMAC_SHA1_96
       - kvno :  
       - Cipher :  [SubSessionKeyEncryptedCipher..]
    * [Decrypted Enc-Part]:
       - AuthTime :  4/13/2020 9:02:40 AM +00:00
       - StartTime :  4/13/2020 9:02:40 AM +00:00
       - EndTime :  4/13/2020 7:02:40 PM +00:00
       - RenewTill :  4/20/2020 9:02:40 AM +00:00
       - Nonce :  637223658
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_SRV_INST
          - Name :  krbtgt
          - Name :  CORPLAB.LOCAL
       - EncryptedPaData :
          - PA_SUPPORTED_ETYPES :
             - Value : 1F000000
          - PA_PAC_OPTIONS :
             - Flags :  BranchAware
       - Key :
          - EType :  RC4_HMAC_NT
          - Value :  79EC0DFC4862771B3A3B3670A25CDD87
       - KeyExpiration :  
       - Flags :  EncryptedPreAuthentication, PreAuthenticated, Renewable, Forwarded, Forwardable
       - LastReq 
          - Type :  0
          - Type :  4/13/2020 9:02:40 AM +00:00

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
                   - kvno :  5
                   - EType :  AES256_CTS_HMAC_SHA1_96
                   - Cipher :  [krbtgtEncryptedCipher...]
             - Authenticator : 
                - kvno :  
                - EType :  AES256_CTS_HMAC_SHA1_96
                - Realm :  CORPLAB.LOCAL
                - SequenceNumber :  637223661
                - Subkey :
                   - EType :  AES256_CTS_HMAC_SHA1_96
                   - KeyValue :  67C23F60765764C740FA6356197D1B82FFDA9552A825001C12A8B0AC39B5639A
                - CTime :  4/13/2020 9:02:40 AM +00:00
                - CuSec :  924
                - CName :  
                   - Type :  NT_PRINCIPAL
                   - Name :  spnuseraes
                - Checksum :
                   - Type :  HMAC_SHA1_96_AES256
                   - Checksum :  7A79582537AFB27AB4142258
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
             - Checksum :  7709AEDE365DE51AF4602FDCF302184D
    * Body :
       - KdcOptions :  EncTktInSkey, RenewableOk, Renewable, Forwardable
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_PRINCIPAL
          - Name :  spnuseraes
       - Till :  9/13/2037 2:48:05 AM +00:00
       - RTime :  
       - Nonce :  637223660
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
          - kvno :  3
          - EType :  AES256_CTS_HMAC_SHA1_96
          - Cipher :  [ServiceEncryptedCipher...]
    * Enc-Part :
       - EType :  AES256_CTS_HMAC_SHA1_96
       - kvno :  
       - Cipher :  [SubSessionKeyEncryptedCipher..]
    * [Decrypted Enc-Part]:
       - AuthTime :  4/13/2020 9:02:40 AM +00:00
       - StartTime :  4/13/2020 9:02:40 AM +00:00
       - EndTime :  4/13/2020 7:02:40 PM +00:00
       - RenewTill :  4/20/2020 9:02:40 AM +00:00
       - Nonce :  637223660
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_PRINCIPAL
          - Name :  spnuseraes
       - EncryptedPaData :
       - Key :
          - EType :  AES256_CTS_HMAC_SHA1_96
          - Value :  F54255C6B5D8D2CA851D1D4C87BA7591AF3BD5EB69213EB29AE0F967D035BB76
       - KeyExpiration :  
       - Flags :  EncryptedPreAuthentication, PreAuthenticated, Renewable, Forwardable
       - LastReq 
          - Type :  0
          - Type :  4/13/2020 9:02:40 AM +00:00
    * [Decrypted Ticket Enc-Part]:
       - AuthTime :  4/13/2020 9:02:40 AM +00:00
       - StartTime :  4/13/2020 9:02:40 AM +00:00
       - EndTime :  4/13/2020 7:02:40 PM +00:00
       - RenewTill :  4/20/2020 9:02:40 AM +00:00
       - CRealm :  CORPLAB.LOCAL
       - CName :
          - Type :  NT_ENTERPRISE
          - Name :  administrator@corplab.local
       - AuthorizationData :
          - Type :  AdIfRelevant
          - Data :  System.ReadOnlyMemory<Byte>[830]
             - Type :  AdWin2kPac
             - Data :  System.ReadOnlyMemory<Byte>[808]
       - CAddr :  
       - Flags :  EncryptedPreAuthentication, PreAuthenticated, Renewable, Forwardable
       - Key :
          - EType :  AES256_CTS_HMAC_SHA1_96
          - Value :  F54255C6B5D8D2CA851D1D4C87BA7591AF3BD5EB69213EB29AE0F967D035BB76
       - Transited :
          - Type :  DomainX500Compress
          - Contents :  

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
                   - kvno :  5
                   - EType :  AES256_CTS_HMAC_SHA1_96
                   - Cipher :  [krbtgtEncryptedCipher...]
             - Authenticator : 
                - kvno :  
                - EType :  AES256_CTS_HMAC_SHA1_96
                - Realm :  CORPLAB.LOCAL
                - SequenceNumber :  637223663
                - Subkey :
                   - EType :  AES256_CTS_HMAC_SHA1_96
                   - KeyValue :  99305994345CF0F07A444AF4BB187153DD870EB12647829862207822E1C2CC3E
                - CTime :  4/13/2020 9:02:40 AM +00:00
                - CuSec :  989
                - CName :  
                   - Type :  NT_PRINCIPAL
                   - Name :  spnuseraes
                - Checksum :
                   - Type :  HMAC_SHA1_96_AES256
                   - Checksum :  E934879EDE4AE878C1C3487A
                - AuthorizationData :  
                - AuthenticatorVersionNumber :  5
       - PA_PAC_OPTIONS :
          - Flags :  ResourceBasedConstrainedDelegation
    * Body :
       - KdcOptions :  RenewableOk, CNameInAdditionalTicket, ConstrainedDelegation, Renewable, Forwardable
       - Realm :  CORPLAB.LOCAL
       - SName :
          - Type :  NT_SRV_INST
          - Name :  cifs
          - Name :  dc1.corplab.local
       - Till :  9/13/2037 2:48:05 AM +00:00
       - RTime :  
       - Nonce :  637223662
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
             - kvno :  3
             - EType :  AES256_CTS_HMAC_SHA1_96
             - Cipher :  [ServiceEncryptedCipher...]

[*] Receiving TGS-REP [S4U2Proxy] ...

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
          - Name :  cifs
          - Type :  NT_SRV_INST
       - EncryptedPart :
          - kvno :  6
          - EType :  AES256_CTS_HMAC_SHA1_96
          - Cipher :  [ServiceEncryptedCipher...]
    * Enc-Part :
       - EType :  AES256_CTS_HMAC_SHA1_96
       - kvno :  
       - Cipher :  [SubSessionKeyEncryptedCipher..]

```