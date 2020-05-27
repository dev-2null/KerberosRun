```powershell
PS C:\Users> .\KerberosRun.exe --asktgt --user normaluser --pass [...] --verbose --decrypttgt [...] --decryptetype aes256

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
       - Nonce :  637261652
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
    - doIFHDCCBRigAwIBBaEDAgEWooIEHDCCBBhhggQUMIIEEKADAgEFoQ8bDUNPUlBMQUIuTE9DQUyiIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDUNPUlBMQUIuTE9DQUyjggPSMIIDzqADAgESoQMCAQuiggPABIIDvEfgVj/yxC+VZo7cNLOYuHHYY7w5VMPCOUEf2UgnY6UutVx3q16gLZDxShRGM5TxB4BZnN8wZQ4d8746tJJgeO2XUE1bBlLSGOk2Vn6ry9iMMr2KwJsW4Ch1ByRqcnwm9/ZQS/w2tl7jbSfPKBsnwqsXk8Q9PbrYnEicLD3RoRDF0N8t5xCnuNLUdqveuqu2yqbRiOfwrkMtnAaR25gUpD0b3YiZtLGzdqFwrpKKPzH+FyTfL8N93Gmb4VzRMsrjMmOaNipi7KbOyCQSK+ZFZK8iX8ffbqGCLxDQ8b8jATrfu9/C7coW4exwu9xgkv4A1eZ7RAynkEgYrZMs58lIDv1Q+xNj77IIjCzing57IRiy71Fiq9f4AObiILpg0mBX4CaGyU9DpqJdhmipTFCnS9Sng9qINkpPv1OrHnj7sNgrAvpHQiLYxL2CYJZj3pEEOxLovepyKyX+Qe6QkYiOsFerIM6lJtM3bmOCAdmrsVQBh6ZF1loy4/V8O4mn3kOGop1ZJFp+6yrejNBDejQ/anBJbcK7xP2ZuXcSaUUo5jalmKmWA+daur/hESjq43L6+mON5MwYZKqovJAJ9tgmnQGdnqxh/MKcPM9HkZXRW+2qeOKxS1mTzorBM6y1H44vVM0J8PiOCNnpShBKRcdu7Ba0znjQW7xF9ur4qoNfLrw45xORb8k4T6xe87IhHQus0vJmUtfV2eBYhb4ySB5msD3PKrdqqRa0NTFYp3jmpXTmMDKlE5x3oVtd6LYnLiiS/3Fn//g+ou97sqtFm2E+/o2j7vAxdQ3z5rcdREaNLVbUMdWIpUbdNIlrPXW6iS25RXVG6xtdl9T4HbxZWr1ef73H25hvdr4w91LgAQ/dfw1EGVJ4OL2mR3R7FYg2ze2WT9YhNOKyeM9iHckxgX44ZmUJacw4HpfYo14jDRpE5qIhNGwiI6KjSQ77rgNPWnWEtUz4zXpRg0DjIK7Wgav57b6dPtUo8w3Vd1pBu0On1IIaf/22/mDicA7/qlN2khAuExkZHkGhG7g76dZqrYzvmGakd9igWqqmoipYxyySMxPn5ekgF3k2XoFYkcc7dfqp9t8sTe53PUGCkjMjGYHOZT+hYw+caa1wWG4YDZHEW1TlHVc09d7UpM4qq/OSVyekKMgrmSHhJfJUJL8UJhrusl7ZLgQoTNIPkk7EQJhXACfXKe7STpIO7K7VI6YS4lTRX7grPdsulCfQP2iPnNVgEiXz8R9CHbCOJHrB07NrcDM3L9UfswPmn5R21sXbo4HrMIHooAMCAQCigeAEgd19gdowgdeggdQwgdEwgc6gKzApoAMCARKhIgQgr5OFtGEwifRTCuucwljGT/XIywbvuqiaAlHKwGryk0uhDxsNQ09SUExBQi5MT0NBTKIXMBWgAwIBAaEOMAwbCm5vcm1hbHVzZXKjBwMFAEDBAAClERgPMjAyMDA1MjcwODMyNTNaphEYDzIwMjAwNTI3MTgzMjUzWqcRGA8yMDIwMDYwMzA4MzI1M1qoDxsNQ09SUExBQi5MT0NBTKkiMCCgAwIBAqEZMBcbBmtyYnRndBsNQ09SUExBQi5MT0NBTA==

```