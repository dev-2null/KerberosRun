```
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