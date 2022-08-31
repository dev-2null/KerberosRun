using CommandLine;
using System;

namespace KerberosRun
{
    [Verb("default", HelpText = "Default options, not visible")]
    public class Options
    {
        public static Options Instance { get; set; }

        [Option("Domain", Default = null, HelpText = "Domain Name")]
        public string Domain { get; set; }

        [Option("User", Default = null, HelpText = "Username")]
        public string User { get; set; }

        [Option("Pass", Default = "password", HelpText = "Password")]
        public string Pass { get; set; }

        [Option("TargetDomain", Default = null, HelpText = "Target Domain Name for the target service")]
        public string TargetDomain { get; set; }

        [Option("Ticket", Default = null, HelpText = "Pass base64 encoded kirbi TGT")]
        public string Ticket { get; set; }

        [Option("DecryptEtype", Default = null, HelpText = "Decrypt Encryption Type")]
        public string DecryptEtype { get; set; }

        [Option("DecryptTGS", Default = null, HelpText = "Decrypt TGS")]
        public string DecryptTGS { get; set; }

        [Option("SrvName", Default = null, HelpText = "Service Account Name for decrypting TGS")]
        public string SrvName { get; set; }

        [Option("AltService", Default = null, HelpText = "Change the service name for a ticket")]
        public string AltService { get; set; }



        [Option("RC4", Default = null, HelpText = "RC4 Hash")]
        public string RC4 { get; set; }

        [Option("AES128", Default = null, HelpText = "AES128 Hash")]
        public string AES128 { get; set; }

        [Option("AES256", Default = null, HelpText = "AES256 Hash")]
        public string AES256 { get; set; }


        [Option("NoPAC", Default = false, HelpText = "No PAC")]
        public bool NoPAC { get; set; }

        [Option("Outfile", Default = false, HelpText = "Write Kirbi file.")]
        public bool Outfile { get; set; }

        [Option("PTT", Default = false, HelpText = "Pass The Ticket into current session")]
        public bool PTT { get; set; }

        [Option("OpSec", Default = true, HelpText = "OpSec")]
        public bool OpSec { get; set; }

        [Option("Verbose", Default = false, HelpText = "Verbose")]
        public bool Verbose { get; set; }

        [Option("Debug", Default = false, HelpText = "Debug")]
        public bool Debug { get; set; }
    }


    [Verb("asktgt", HelpText = "Ask for a TGT.")]
    class AskTGTOptions : Options
    {
        [Option("DecryptTGT", Default = null, HelpText = "Decrypt TGT")]
        public string DecryptTGT { get; set; }
    }

    [Verb("asktgs", HelpText = "Ask for a TGS.")]
    class AskTGSOptions : Options
    {
        [Option("SPN", Default = null, HelpText = "SPN")]
        public string SPN { get; set; }

        [Option("SPNs", Default = null, HelpText = "SPN")]
        public string SPNs { get; set; }
    }

    [Verb("s4u", HelpText = "Perform S4U.")]
    class S4UOptions : Options
    {
        [Option("SPN", Required = true, Default = null, HelpText = "SPN")]
        public string SPN { get; set; }

        [Option("Impersonateuser", Required = true, HelpText = "Impersonate Username")]
        public string ImpersonateUser { get; set; }
    }

    [Verb("s4u2self", HelpText = "Perform S4U2Self.")]
    class S4U2SelfOptions : Options
    {
        [Option("Impersonateuser", Required = true, HelpText = "Impersonate Username")]
        public string ImpersonateUser { get; set; }
    }


    [Verb("kerberoast", HelpText = "Perform Kerberoasting.")]
    class KerberoastOptions : Options
    {
        [Option("SPN", Default = null, HelpText = "SPN")]
        public string SPN { get; set; }

        [Option("SPNs", Default = null, HelpText = "SPN")]
        public string SPNs { get; set; }

        [Option("Format", Default = "hashcat", HelpText = "Hash Format")]
        public string Format { get; set; }
    }

    [Verb("asreproast", HelpText = "Perform Asreproasting.")]
    class AsreproastOptions : Options
    {
        [Option("Target", Default = null, Required = true, HelpText = "Target AS-REP roast user")]
        public string Target { get; set; }

        [Option("Format", Default = "hashcat", HelpText = "Hash Format")]
        public string Format { get; set; }
    }

    [Verb("golden", HelpText = "Build a golden ticket.")]
    class GoldentOptions : Options
    {

        [Option("UserID", Default = 500, HelpText = "User ID")]
        public int UserID { get; set; }

        [Option("DomainSID", Required = true,  Default = null, HelpText = "Domain SID")]
        public string DomainSID { get; set; }

        [Option("Impersonateuser", Required = true,  Default = null, HelpText = "Impersonate Username")]
        public string ImpersonateUser { get; set; }
    }

    [Verb("silver", HelpText = "Build a silver ticket.")]
    class SilverOptions : Options
    {

        [Option("Impersonateuser", Required = true, Default = null, HelpText = "Impersonate Username")]
        public string ImpersonateUser { get; set; }

        [Option("Host", Required = true,  Default = null, HelpText = "Target Server")]
        public string Host { get; set; }

        [Option("Service", Required = true,  Default = null, HelpText = "Service for a sliver ticket")]
        public string Service { get; set; }

        [Option("DomainSID", Required = true, Default = null, HelpText = "Domain SID")]
        public string DomainSID { get; set; }
    }

    [Verb("ptt", HelpText = "Pass a ticket into memory.")]
    class PTTOptions : Options
    {

    }


}
