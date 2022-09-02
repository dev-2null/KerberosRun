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
    public class TGT: KerberosService
    {
        private KrbAsReq asReqMessage;
        internal KrbAsRep asRep;
        private KrbEncAsRepPart asDecryptedRepPart;
        internal KrbEncryptionKey sessionKey;
        AuthenticationOptions authOptions = AuthenticationOptions.RenewableOk |
                                            AuthenticationOptions.Canonicalize |
                                            AuthenticationOptions.Renewable |
                                            AuthenticationOptions.Forwardable |
                                            AuthenticationOptions.RepPartCompatible;

        public TGT(): base()
        {
            if (!KerberosRun.NoPAC) { authOptions |= AuthenticationOptions.IncludePacRequest; }
        }


        public override void Create()
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
                        Name = new[] { KerberosRun.User }// + "@" + domainName.ToUpper() }
                    },
                    //KrbPrincipalName.FromString(
                    //    username,
                    //   PrincipalNameType.NT_ENTERPRISE,
                    //    domainName
                    //),
                    EType = KerberosRun.UseRC4 ? new[] { EncryptionType.RC4_HMAC_NT } : KrbConstants.KerberosConstants.ETypes.ToArray(),//KrbConstants.KerberosConstants.ETypes.ToArray(),//kdcReqEtype, 
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


            if (authOptions.HasFlag(AuthenticationOptions.PreAuthenticate) && !KerberosRun.Asreproast)
            //if (!KerberosRun.Asreproast)
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



        public override async Task Ask()
        {

            logger.Info("[*] Starting Kerberos Authentication ...");
            //Pre-Auth
            bool notPreauth = true;

            while (notPreauth)
            {
                try
                {
                    logger.Info("[*] Sending AS-REQ to {0}...", KerberosRun.DC);

                    Create();

                    var asReq = asReqMessage.EncodeApplication();
        
                    asRep = await transport.SendMessage<KrbAsRep>(
                        KerberosRun.DC ?? KerberosRun.Domain,
                        asReq,
                        default);
                    logger.Info("[*] Receiving AS-REP...");
                    if (KerberosRun.Asreproast) { return; }
                }
                catch (KerberosProtocolException pex)
                {
                    logger.Info("[x] {0}", pex.Message);

                    if (pex?.Error?.ErrorCode == KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED)
                    {
                        if (KerberosRun.Asreproast)
                        {
                            logger.Error("[x] Sorry the provided user requires PreAuth.\n");
                            Environment.Exit(1);
                        }

                        //Salt issue for RID 500 Built-in admin account
                        //https://github.com/dotnet/Kerberos.NET/issues/164
                        cred.IncludePreAuthenticationHints(pex?.Error?.DecodePreAuthentication());
                        authOptions |= AuthenticationOptions.PreAuthenticate;
                        logger.Info("[*] Adding encrypted timestamp ...");
                        continue;


                    }
                    else if (pex?.Error?.ErrorCode == KerberosErrorCode.KDC_ERR_PREAUTH_FAILED)
                    {
                        logger.Error("[x] Invalid Credential! Authentication Stopped ...\n");
                        requestFailed = true;
                    }
                    else
                    {
                        logger.Error("[x] Authentication Stopped ...\n");
                        requestFailed = true;
                    }
                    Environment.Exit(0);
                }
                notPreauth = false;
            }


            ticket = asRep.Ticket;
            try
            {
                asDecryptedRepPart = cred.DecryptKdcRep(
                           asRep,
                           KeyUsage.EncAsRepPart,
                           d => KrbEncAsRepPart.DecodeApplication(d));
            }
            catch
            {
                logger.Error("[x] Invalid Credential!\n");
                Environment.Exit(0);
            }
            
            sessionKey = asDecryptedRepPart.Key;
            bKirbi = Kirbi.GetKirbi(asRep, asDecryptedRepPart, KerberosRun.PTT);;
        }



        public override void Display()
        {
            if (!KerberosRun.Verbose) { return; }
            //AS-Req Part
            logger.Info("[*] AS-REQ");
            Displayer.PrintReq(asReqMessage, cred.CreateKey());

            //AS-Rep Part
            logger.Info("[*] AS-REP");
            Displayer.PrintRep(asRep, cred.CreateKey());


            if (authOptions.HasFlag(AuthenticationOptions.PreAuthenticate))
            {
                Console.WriteLine("    * [Decrypted Enc-Part]:");

                Displayer.PrintRepEnc(asDecryptedRepPart, cred.CreateKey());



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

                if (!string.IsNullOrEmpty(KerberosRun.DecryptTGT))
                {
                    var krbtgtCred = new KerberosHashCreds("krbtgt", KerberosRun.DecryptTGT, KerberosRun.DecryptEtype);

                    //TGS - REQ Ticket Enc-Part
                    var ticketDecrypted = asRep.Ticket.EncryptedPart.Decrypt
                        (krbtgtCred.CreateKey(),
                        KeyUsage.Ticket,
                        b => KrbEncTicketPart.DecodeApplication(b));
                    Console.WriteLine("   * [Decrypted TGT]:");
                    Displayer.PrintTicketEnc(ticketDecrypted);
                    //Encrypt the ticket again
                    asRep.Ticket.EncryptedPart = KrbEncryptedData.Encrypt(ticketDecrypted.EncodeApplication(),
                        krbtgtCred.CreateKey(), KeyUsage.Ticket);
                }
            }

        }

        public override void ToFile()
        {
            Utils.WriteBytesToFile(Utils.MakeTicketFileName(KerberosRun.User), bKirbi);
        }

    }
}
