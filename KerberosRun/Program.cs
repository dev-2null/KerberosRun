﻿using System;
using System.DirectoryServices.ActiveDirectory;
using System.Threading.Tasks;
using CommandLine;
using CommandLine.Text;
using Kerberos.NET.Entities;

namespace KerberosRun
{
    public class Program
    {

        public static void Main(string[] args)
        {
            Displayer.PrintBanner();

            var parserResult = new Parser(with => {
                with.CaseInsensitiveEnumValues = true;
                with.CaseSensitive = false; 
                with.HelpWriter = null; 
            }).ParseArguments<AskTGTOptions, AskTGSOptions, 
            KerberoastOptions, AsreproastOptions, 
            S4UOptions, S4U2SelfOptions, U2UOptions,
            GoldentOptions, SilverOptions, PTTOptions>(args);


            parserResult.MapResult(
                    (AskTGTOptions options) => new KerberosRun(options).GetTGT(out _),
                    (AskTGSOptions options) => new KerberosRun(options).GetTGS(),
                    (S4U2SelfOptions options) => new KerberosRun(options).GetS4U2Self(out _),
                    (S4UOptions options) => new KerberosRun(options).GetS4U(out _),
                    (U2UOptions options) => new KerberosRun(options).GetU2U(out _),
                    (KerberoastOptions options) => new KerberosRun(options).Kerberoasting(),
                    (AsreproastOptions options) => new KerberosRun(options).Asreproasting(),
                    (GoldentOptions options) => new KerberosRun(options).GetGolden(),
                    (SilverOptions options) => new KerberosRun(options).GetSilver(),
                    (PTTOptions options) => new KerberosRun(options).PassTheTicket(),
                    errs => DisplayHelp()//parserResult)
            );
            Console.WriteLine();

        }

        public static int DisplayHelp()//ParserResult<object> parserResult)
        {
            //Console.WriteLine(HelpText.AutoBuild(parserResult, h => {
            //    h.AdditionalNewLineAfterOption = false;
            //    h.Heading = " Version 2.0.3";
            //    h.Copyright = "";
            //    return h;
            //}));

            var help = @"

    asktgt      --User user --Pass pass|--RC4 Hash|--AES128 Hash|--AES256 Hash [--Domain domain] [--NoPAC] [--Verbose] [--Outfile] [--PTT]
    
    asktgs      --SPN Svc/Host|--SPNs Svc1/Host1,Svc2/Host2 [--User user] [--Pass pass|--RC4 Hash|--AES128 Hash|--AES256 Hash] [--AltService SvcAlt/Host] [--Domain domain] [--TargetDomain targetdomain] [--Ticket Base64Kirbi] [--NoPAC] [--Verbose] [--Outfile] [--PTT]

    s4u2self    --User user --ImperonsateUser ipuser [--Pass pass|--RC4 Hash|--AES128 Hash|--AES256 Hash] [--Domain domain] [--Ticket Base64Kirbi] [--NoPAC] [--Verbose] [--Outfile] [--PTT]
    
    s4u         --User user --ImperonsateUser ipuser --SPN Svc/Host [--Pass pass|--RC4 Hash|--AES128 Hash|--AES256 Hash] [--AltService SvcAlt/Host] [--Domain domain] [--Ticket Base64Kirbi] [--NoPAC] [--Verbose] [--Outfile] [--PTT]

    u2u         --User user --TargetUser tuser --TargetTGT Base64TGT [--PACUser pacuser] [--Pass pass|--RC4 Hash|--AES128 Hash|--AES256 Hash] [--Ticket Base64Kirbi] [--NoPAC] [--Verbose] [--Outfile] [--PTT]

    kerberoast  [--User user] [--Pass pass|--RC4 Hash|--AES128 Hash|--AES256 Hash] --SPN Svc/Host|--SPNs Svc1/Host1,Svc2/Host2

    asreproast  --Target user [--Format hashcat/john]

    golden      --RC4 Hash|--AES128 Hash|--AES256 Hash --Domain domain --DomainSID domainsid --ImpersonateUser ipuser --UserID uid  [--PTT]

    silver      --Host host --RC4 Hash|--AES128 Hash|--AES256 Hash --Domain domain --DomainSID domainsid --ImpersonateUser ipuser --Service svc [--PTT]

    ptt         --Ticket base64ticket

                ";
            Console.WriteLine(help);
            return 1;
        }



    }

}


