
# KerberosRun

KerberosRun is a little tool I use to study Kerberos internals together with my [ADCollector](https://github.com/dev-2null/ADCollector). I'll try to learn and implement stuff from [Rubeus](https://github.com/GhostPack/Rubeus), also something not in Rubeus.  

KerberosRun uses the [Kerberos.NET](https://github.com/dotnet/Kerberos.NET) library built by [Steve Syfuhs](https://twitter.com/stevesyfuhs). It is heavily adapated from [Harmj0y](https://twitter.com/harmj0y)'s Rubeus project (some code were taken directly from this project). 

[dev2null](https://twitter.com/dev2nulI) is the primary author of this project. My colleague [Constantin](https://twitter.com/_Herberos) is the collaborator who helped me build up the tool, had a lot of discussions with me and gave me ideas. 

Thanks Steve for builting up this great library and having discussions with me to solve code problems. Thanks Harmj0y (and other authors) for the concepts and weaponization in Rubeus. Special thanks to [@_dirkjan](https://twitter.com/_dirkjan) for helping me out regarding the KRBCRED structure and other questions.


## Usage
```powershell
PS C:\Users\dev2null\Desktop> .\KerberosRun.exe

   __           __
  / /_____ ____/ /  ___ _______  ___ ______ _____
 /  '_/ -_) __/ _ \/ -_) __/ _ \(_-</ __/ // / _ \
/_/\_\\__/_/ /_.__/\__/_/  \___/___/_/  \_,_/_//_/

 v2.0.3
 by dev2null



    asktgt      [--User user] [--Pass pass|--RC4 Hash|--AES128 Hash|--AES256 Hash] [--TGTDeleg CIFS/DC] [--Domain domain] [--DC dc] [--UseRC4] [--NoPAC] [--Verbose] [--Outfile] [--PTT]

    asktgs      --SPN Svc/Host|--SPNs Svc1/Host1,Svc2/Host2 [--User user] [--Pass pass|--RC4 Hash|--AES128 Hash|--AES256 Hash|--Ticket Base64Kirbi] [--TGTDeleg CIFS/DC] [--AltService SvcAlt/Host] [--Domain domain] [--DC dc] [--UseRC4] [--TargetDomain targetdomain] [--NoPAC] [--Verbose] [--Outfile] [--PTT]

    s4u2self    --ImperonsateUser ipuser [--User user] [--Pass pass|--RC4 Hash|--AES128 Hash|--AES256 Hash|--Ticket Base64Kirbi] [--TGTDeleg CIFS/DC] [--Domain domain] [--DC dc] [--UseRC4] [--NoPAC] [--Verbose] [--Outfile] [--PTT]

    s4u         --ImperonsateUser ipuser --SPN Svc/Host [--User user] [--Pass pass|--RC4 Hash|--AES128 Hash|--AES256 Hash|--Ticket Base64Kirbi] [--TGTDeleg CIFS/DC] [--AltService SvcAlt/Host] [--Domain domain] [--DC dc] [--UseRC4] [--NoPAC] [--Verbose] [--Outfile] [--PTT]

    u2u         --TargetUser tuser --TargetTGT Base64TGT [--User user] [--Pass pass|--RC4 Hash|--AES128 Hash|--AES256 Hash|--Ticket Base64Kirbi] [--TGTDeleg CIFS/DC] [--PACUser pacuser] [--Domain domain] [--DC dc] [--UseRC4] [--NoPAC] [--Verbose] [--Outfile] [--PTT]

    kerberoast  --SPN Svc/Host|--SPNs Svc1/Host1,Svc2/Host2 [--User user] [--Pass pass|--RC4 Hash|--AES128 Hash|--AES256 Hash] [--TGTDeleg CIFS/DC] [--UseRC4] [--Domain domain] [--DC dc]

    asreproast  --Target user [--Format hashcat/john] [--Domain domain] [--DC dc]

    golden      --RC4 Hash|--AES128 Hash|--AES256 Hash --Domain domain --DomainSID domainsid --ImpersonateUser ipuser --UserID uid  [--PTT]

    silver      --Host host --RC4 Hash|--AES128 Hash|--AES256 Hash --Domain domain --DomainSID domainsid --ImpersonateUser ipuser --Service svc [--PTT]

    ptt         --Ticket base64ticket
```


## License
KerberosRun has an MIT License. See the [License File](/LICENSE) for more details. Also see the [Notices file](/NOTICES) for more information on the licenses of projects this depends on.