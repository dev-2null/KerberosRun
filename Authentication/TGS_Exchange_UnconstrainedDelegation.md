```
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

```