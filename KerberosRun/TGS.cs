using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace KerberosRun
{
    public class TGS: KerberosService
    {
        private static KrbTicket tgt;
        private static KrbEncryptionKey sessionKey;
        private KrbEncryptionKey subSessionKey;
        private KrbTgsReq tgsReq;
        internal KrbTgsRep tgsRep;
        internal bool isReferral = false;
        internal KrbEncryptionKey referralSessionKey;
        internal List<KrbTicket>  additionalTickets = new List<KrbTicket>();
        private KrbEncTgsRepPart tgsDecryptedRepPart;
        private string clientName;
        internal static string domain;


        public TGS(KrbTicket ticket, KrbEncryptionKey key) : base()
        {
            tgt = ticket;
            sessionKey = key;
        }


        public TGS(TGT myTGT) : this(tgt, sessionKey)
        {
            tgt = myTGT.ticket;
            sessionKey = myTGT.sessionKey;
        }

        public TGS(string tgtKirbi): this(tgt, sessionKey)
        {
            logger.Info("[*] Using base64 kirbi TGT...");
            var info = Kirbi.GetTicketFromKirbi(tgtKirbi);
            tgt = info.Ticket;
            sessionKey = info.SessionKey;
            clientName = info.CNAME;
        }


        public override void Create()
        {
            //Request Service Ticket parameters
            ApOptions apOptions = ApOptions.Reserved;
            KdcOptions kdcOptions = KdcOptions.Forwardable |
                                    KdcOptions.Renewable |
                                    //KdcOptions.RenewableOk |
                                    KdcOptions.Canonicalize;

            //when performing S4U2Proxy, this should be null
            string s4u = (KerberosRun.S4UTicket == null) ? KerberosRun.ImpersonateUser : null;

            //U2U requires EncTktInSkey in KDC options
            KrbTicket u2uServerTicket = KerberosRun.U2UTicket ?? null;
            if (u2uServerTicket != null) { kdcOptions |= KdcOptions.EncTktInSkey; }

            //if (isUnconstrained)
            //{
            //    spn = $"krbtgt/{KerberosRun.Domain}";
            //    kdcOptions |= KdcOptions.Forwarded;
            //}

            var rst = new RequestServiceTicket()
            {
                ServicePrincipalName = KerberosRun.SPN,
                ApOptions = apOptions,
                S4uTarget = s4u,
                S4uTicket = KerberosRun.S4UTicket,
                UserToUserTicket = u2uServerTicket,
                KdcOptions = kdcOptions,
                Realm = domain
            };

            
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


            EncryptionType[] etype = KrbConstants.KerberosConstants.ETypes.ToArray();//KerberosRun.OpSec ? KrbConstants.KerberosConstants.ETypes.ToArray() : new[] { EncryptionType.RC4_HMAC_NT };

            var name = string.IsNullOrEmpty(KerberosRun.User) ? new string[] { clientName } : new string[] { KerberosRun.User };

            KrbPrincipalName cname = new KrbPrincipalName()
            {
                Type = PrincipalNameType.NT_PRINCIPAL,
                Name = name
            };

            KrbPrincipalName sname;
            //TGS / S4U2Self / U2U
            if (KerberosRun.S4UTicket == null)
            {
                //U2U
                if (u2uServerTicket != null)
                {
                    sname = new KrbPrincipalName()
                    {
                        Type = PrincipalNameType.NT_PRINCIPAL,
                        Name = new string[] { KerberosRun.U2UTarget } 
                    };
                }
                //TGS / S4U2Self
                else
                {
                    //if we are not impersonating, we are requesting SPN
                    string[] sn = string.IsNullOrEmpty(KerberosRun.ImpersonateUser) ? rst.ServicePrincipalName.Split('/', '@') : new string[] { KerberosRun.User };
                    sname = new KrbPrincipalName()
                    {
                        Type = PrincipalNameType.NT_PRINCIPAL,
                        Name = sn
                    };
                }
            }
            //S4U2Proxy
            else
            {
                sname = new KrbPrincipalName()
                {
                    Type = PrincipalNameType.NT_PRINCIPAL,
                    Name = rst.ServicePrincipalName.Split('/', '@')
                };
            }


            var body = new KrbKdcReqBody
            {
                //Specify RC4 as the only supported EType
                EType = etype,
                KdcOptions = rst.KdcOptions,
                Nonce = KrbConstants.KerberosConstants.GetNonce(),
                Realm = rst.Realm,
                SName = sname,
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
                CName = cname,
                Realm = KerberosRun.Domain,//This should be the user domain (inside the referral TGT)
                SequenceNumber = KrbConstants.KerberosConstants.GetNonce(),
                Checksum = bodyChecksum,
                CTime = now,
                CuSec = now.Millisecond //new Random().Next(0, 999999)
            };

            subSessionKey = KrbEncryptionKey.Generate(sessionKey.EType);
            subSessionKey.Usage = KeyUsage.EncTgsRepPartSubSessionKey;
            authenticator.Subkey = subSessionKey;

            KrbEncryptedData encryptedAuthenticator = null;
            try
            {
                encryptedAuthenticator = KrbEncryptedData.Encrypt(
                    authenticator.EncodeApplication(),
                    sessionKey.AsKey(),
                    KeyUsage.PaTgsReqAuthenticator);

            }
            catch (Exception e)
            {
                logger.Error("[x] {0}", e.Message);
                Environment.Exit(1);
            }

            var apReq = new KrbApReq
            {
                Ticket = tgt,
                ApOptions = apOptions,
                Authenticator = encryptedAuthenticator
            };


            var pacOptions = new KrbPaPacOptions
            {
                Flags =  (KerberosRun.S4UTicket == null) ? PacOptions.BranchAware : PacOptions.ResourceBasedConstrainedDelegation
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


            //Only include PA_FOR_USER when perform U2U for self to self
            if (!string.IsNullOrWhiteSpace(rst.S4uTarget) || ((rst.UserToUserTicket != null) && (KerberosRun.U2UTarget == KerberosRun.User)))
            {
                KrbPaForUser paS4u;

                //U2U 
                if (rst.UserToUserTicket != null)
                {
                    paS4u = new KrbPaForUser
                    {
                        AuthPackage = "Kerberos",
                        UserName = new KrbPrincipalName()
                        {
                            Type = PrincipalNameType.NT_PRINCIPAL,
                            Name = new string[] { KerberosRun.U2UPACUser }
                        },
                        UserRealm = KerberosRun.Domain
                    };
                }
                //S4U2Self
                else
                {
                    paS4u = new KrbPaForUser
                    {
                        AuthPackage = "Kerberos",
                        UserName = new KrbPrincipalName { Type = PrincipalNameType.NT_ENTERPRISE, Name = new[] { s4u } },
                        UserRealm = KerberosRun.Domain
                    };
                }
                

                //TGS accepts sessionKey/subSessionKey whereas S4U2Self only accepts sessionKey, otherwise KRB_AP_ERR_MODIFIED
                paS4u.GenerateChecksum(sessionKey.AsKey());

                paData.Add(new KrbPaData
                {
                    Type = PaDataType.PA_FOR_USER,
                    Value = paS4u.Encode()
                });
            }

            tgsReq = new KrbTgsReq
            {
                PaData = paData.ToArray(),
                Body = body
            };

        }


        public override async Task Ask()
        {
            domain = isReferral ? KerberosRun.TargetDomain : KerberosRun.Domain;

            Create();

            var encodedTgs = tgsReq.EncodeApplication();

            logger.Info("[*] Sending TGS-REQ ...");
            if (KerberosRun.Verbose) { Displayer.PrintReq(tgsReq, cred.CreateKey(), sessionKey.AsKey()); }

            CancellationToken cancellation = default;
            cancellation.ThrowIfCancellationRequested();

            try
            {
                tgsRep = await transport.SendMessage<KrbTgsRep>(
                    domain,
                    encodedTgs,
                    cancellation
                );
            }
            catch (KerberosProtocolException pex)
            {
                logger.Error("[x] {0}\n", pex.Message);
                requestFailed = true;
                return;
            }


            logger.Info("[*] Receiving TGS-REP ...");
            if (KerberosRun.Verbose) { Displayer.PrintRep(tgsRep, cred.CreateKey()); }

            ticket = tgsRep.Ticket;

            //TGS-REP Enc-Part
            tgsDecryptedRepPart = tgsRep.EncPart.Decrypt<KrbEncTgsRepPart>(
                subSessionKey.AsKey(),
                KeyUsage.EncTgsRepPartSubSessionKey,
                (ReadOnlyMemory<byte> t) => KrbEncTgsRepPart.DecodeApplication(t));

            //alternative service name
            if (KerberosRun.AltService != null)
            {
                logger.Info("[*] Replacing TGS service name with {0}",KerberosRun.AltService);
                var subSrvName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_PRINCIPAL,
                    Name = KerberosRun.AltService.Split('/')
                };
                tgsDecryptedRepPart.SName = subSrvName;
                tgsRep.Ticket.SName = subSrvName;
            }

            bKirbi = Kirbi.GetKirbi(tgsRep, tgsDecryptedRepPart, KerberosRun.PTT);

            if (tgsRep.Ticket.SName.Name[0] == "krbtgt")
            {
                logger.Info("[*] Referral TGT received ...");
                isReferral = true;
                referralSessionKey = tgsDecryptedRepPart.Key;
            }
            //var returnFlag = TicketFlags.Anonymous;
        }



        public override void Display()
        {
            if (!KerberosRun.Verbose) { return; }
            Displayer.PrintReq(tgsReq, cred.CreateKey(), sessionKey.AsKey());

            Displayer.PrintRep(tgsRep, cred.CreateKey());

            Console.WriteLine("    * [Decrypted Enc-Part]:");
            Displayer.PrintRepEnc(tgsDecryptedRepPart, cred.CreateKey());

            if (!string.IsNullOrEmpty(KerberosRun.DecryptTGS))
            {
                //=========================================
                //TGS Tiket Enc-Part
                //Service account Cred
                var kerbCred2 = new KerberosHashCreds(KerberosRun.SrvName, KerberosRun.DecryptTGS, KerberosRun.DecryptEtype);

                //TGS-REQ Ticket Enc-Part
                KrbEncTicketPart ticketDecrypted = tgsRep.Ticket.EncryptedPart.Decrypt(
                    kerbCred2.CreateKey(),
                    KeyUsage.Ticket,
                    (ReadOnlyMemory<byte> t) => KrbEncTicketPart.DecodeApplication(t));

                Console.WriteLine("    * [Decrypted Ticket Enc-Part]:");
                Displayer.PrintTicketEnc(ticketDecrypted);
                //=========================================
            }
            if (!string.IsNullOrEmpty(KerberosRun.ImpersonateUser) && KerberosRun.S4UTicket == null)
            {
                KrbEncTicketPart ticketDecrypted = tgsRep.Ticket.EncryptedPart.Decrypt(
                    cred.CreateKey(),
                    KeyUsage.Ticket,
                    (ReadOnlyMemory<byte> t) => KrbEncTicketPart.DecodeApplication(t));
                Console.WriteLine("    * [Decrypted Ticket Enc-Part]:");
                Displayer.PrintTicketEnc(ticketDecrypted);
            }
            if (KerberosRun.U2UTarget != null)
            {
                KrbEncTicketPart ticketDecrypted = tgsRep.Ticket.EncryptedPart.Decrypt(
                    KerberosRun.U2USessionKey.AsKey(),
                    KeyUsage.Ticket,
                    (ReadOnlyMemory<byte> t) => KrbEncTicketPart.DecodeApplication(t));
                Console.WriteLine("    * [Decrypted Ticket Enc-Part]:");
                Displayer.PrintTicketEnc(ticketDecrypted);
            }


        }


        public override void ToFile()
        {
            Utils.WriteBytesToFile(Utils.MakeTicketFileName(KerberosRun.User, KerberosRun.SPN.Split('/')), bKirbi);
        }


    }
}
