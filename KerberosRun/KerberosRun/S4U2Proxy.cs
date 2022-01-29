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

    //S4U2Proxy
    //[MS-SFU] 3.2.5.2.1.2 Using ServicesAllowedToSendForwardedTicketsTo
    //The KDC checks if the security principal name(SPN) for Service 2, 
    //identified in the sname and srealm fields of the KRB_TGS_REQ message, 
    //is in the Service 1 account's ServicesAllowedToSendForwardedTicketsTo parameter. 
    //If it is, then the KDC replies with a service ticket for Service 2. 
    //Otherwise the KDC MUST return `KRB-ERR-BADOPTION`.
    public class S4U2Proxy: KerberosService
    {
        private static KrbTicket tgt;
        private static KrbEncryptionKey sessionKey;
        private KrbTicket s4uTicket;
        private KrbEncryptionKey subSessionKey;
        private KrbTgsReq tgsReq;
        private KrbTgsRep tgsRep;
        private KrbEncTgsRepPart tgsDecryptedRepPart;
        private string clientName;


        public S4U2Proxy(KrbTicket TGT, KrbEncryptionKey key, KrbTicket ticket): base()
        {
            tgt = TGT;
            s4uTicket = ticket;
            sessionKey = key;
        }


        public S4U2Proxy(string tgtKirbi, KrbTicket ticket) : this(tgt, sessionKey, ticket)
        {
            var info = Kirbi.GetTicketFromKirbi(tgtKirbi);
            tgt = info.Ticket;
            sessionKey = info.SessionKey;
            clientName = info.CNAME;
        }


        public S4U2Proxy(TGT myTGT, KrbTicket ticket) : this(tgt, sessionKey, ticket)
        {
            tgt = myTGT.ticket;
            sessionKey = myTGT.sessionKey;
        }

        public override void Create()
        {
            //Request Service Ticket parameters

            ApOptions apOptions = ApOptions.Reserved;
            KdcOptions kdcOptions =
            KdcOptions.Forwardable |
            KdcOptions.Renewable |
            KdcOptions.RenewableOk;
            string s4u = null;
            KrbTicket u2uServerTicket = null;
            string spn = Options.Instance.Spn;


            var rst = new RequestServiceTicket()
            {
                ServicePrincipalName = spn,
                ApOptions = apOptions,
                S4uTarget = s4u,
                S4uTicket = s4uTicket,
                UserToUserTicket = u2uServerTicket,
                KdcOptions = kdcOptions,
                Realm = s4uTicket.Realm
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

            var sname = rst.ServicePrincipalName.Split('/', '@');
            var body = new KrbKdcReqBody
            {
                EType = KrbConstants.KerberosConstants.ETypes.ToArray(),
                KdcOptions = rst.KdcOptions,
                Nonce = KrbConstants.KerberosConstants.GetNonce(),
                Realm = rst.Realm,
                SName = new KrbPrincipalName()
                {
                    Type = PrincipalNameType.NT_PRINCIPAL,
                    Name = sname
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
                Name = name// + "@" + domainName.ToUpper() }
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
            Create();

            var encodedTgs = tgsReq.EncodeApplication();

            logger.Info("[*] Sending TGS-REQ [S4U2Proxy] ...");
            if (Options.Instance.Verbose) { Displayer.PrintReq(tgsReq, cred.CreateKey(), sessionKey.AsKey()); }

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


            logger.Info("[*] Receiving TGS-REP [S4U2Proxy] ...");



            tgsDecryptedRepPart = tgsRep.EncPart.Decrypt<KrbEncTgsRepPart>(
                    subSessionKey.AsKey(),
                    KeyUsage.EncTgsRepPartSubSessionKey,
                    (ReadOnlyMemory<byte> t) => KrbEncTgsRepPart.DecodeApplication(t));

            bKirbi = Kirbi.GetKirbi(tgsRep, tgsDecryptedRepPart, Options.Instance.PTT);

        }



        public override void Display()
        {
            if (!Options.Instance.Verbose) { return; }

            Displayer.PrintRep(tgsRep, cred.CreateKey());

            Console.WriteLine("    * [Decrypted Enc-Part]:");
            Displayer.PrintRepEnc(tgsDecryptedRepPart, cred.CreateKey());
        }

        public override void ToFile()
        {
            Utils.WriteBytesToFile(Utils.MakeTicketFileName(Options.Instance.ImpersonateUser, Options.Instance.Spn.Split('/')), bKirbi);
        }


    }
}
