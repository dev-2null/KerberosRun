using System;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System.Linq;
using System.Text.RegularExpressions;

namespace KerberosRun
{
    class PrintFunc
    {


        public static void PrintBanner()
        {
            Console.WriteLine();
            Console.WriteLine(@"   __           __              ");
            Console.WriteLine(@"  / /_____ ____/ /  ___ _______  ___ ______ _____ ");
            Console.WriteLine(@" /  '_/ -_) __/ _ \/ -_) __/ _ \(_-</ __/ // / _ \");
            Console.WriteLine(@"/_/\_\\__/_/ /_.__/\__/_/  \___/___/_/  \_,_/_//_/");
            Console.WriteLine();
            Console.WriteLine("  v1.0.0");
        }
        //PaData
        public static void PrintPaData(KrbPaData[] paData, KerberosKey key, string decrypted = "", KerberosKey sessionKey = null)
        {
            if (paData != null)
            {
                foreach (var data in paData)
                {
                    if (data.Type == PaDataType.PA_SUPPORTED_ETYPES)
                    {
                        var etypes = paData.FirstOrDefault(p => p.Type == PaDataType.PA_SUPPORTED_ETYPES);
                        //var encryptedEtypes = KrbETypeList.Decode(etypes.Value);

                        Console.WriteLine("{0}       - {1} :", decrypted, etypes.Type);
                        Console.WriteLine("{0}          - Value : {1}", decrypted, (BitConverter.ToString(etypes.Value.ToArray())).Replace("-", ""));
                    }
                    else if (data.Type == PaDataType.PA_ENC_TIMESTAMP)
                    {
                        var timestampPaData = paData.FirstOrDefault(p => p.Type == PaDataType.PA_ENC_TIMESTAMP);
                        var encryptedTimestamp = KrbEncryptedData.Decode(timestampPaData.Value);

                        Console.WriteLine("       - {0} : ", timestampPaData.Type);
                        Console.WriteLine("          - EType :  {0}", encryptedTimestamp.EType);
                        Console.WriteLine("          - kvno :  {0}", encryptedTimestamp.KeyVersionNumber);
                        Console.WriteLine("          - Cipher :  [ClientEncryptedTimestamp...]");
                        //Console.WriteLine("          - Cipher :  {0}", (BitConverter.ToString(encryptedTimestap.Cipher.ToArray())).Replace("-", ""));

                        var timeStamp = encryptedTimestamp.Decrypt(key, KeyUsage.PaEncTs, d => KrbPaEncTsEnc.Decode(d));

                        Console.WriteLine("          - PaTimestamp :  {0}", timeStamp.PaTimestamp);
                        Console.WriteLine("          - PaUSec :  {0}", timeStamp.PaUSec);
                    }
                    else if (data.Type == PaDataType.PA_PAC_REQUEST)
                    {
                        var pacReq = paData.FirstOrDefault(p => p.Type == PaDataType.PA_PAC_REQUEST);
                        var decodedPac = KrbPaPacRequest.Decode(pacReq.Value);

                        Console.WriteLine("       - {0} :", pacReq.Type);
                        Console.WriteLine("          - IncludePac :  {0}", decodedPac.IncludePac);
                    }
                    else if (data.Type == PaDataType.PA_PAC_OPTIONS)
                    {
                        var options = paData.FirstOrDefault(p => p.Type == PaDataType.PA_PAC_OPTIONS);
                        var decodedOptions = KrbPaPacOptions.Decode(options.Value);

                        Console.WriteLine("{0}       - {1} :", decrypted, options.Type);
                        Console.WriteLine("{0}          - Flags :  {1}", decrypted, decodedOptions.Flags);
                    }
                    else if (data.Type == PaDataType.PA_ETYPE_INFO2)
                    {
                        var info2Enc = paData.FirstOrDefault(p => p.Type == PaDataType.PA_ETYPE_INFO2);
                        var decodedInfo2 = info2Enc.DecodeETypeInfo2().FirstOrDefault();
                        Console.WriteLine("       - {0} :", info2Enc.Type);
                        Console.WriteLine("          - EType :  {0}", decodedInfo2.EType);
                        Console.WriteLine("          - S2kParams :  {0}", decodedInfo2.S2kParams);
                        Console.WriteLine("          - Salt :  {0}", decodedInfo2.Salt);
                    }
                    else if (data.Type == PaDataType.PA_FOR_USER)
                    {
                        var users = paData.FirstOrDefault(p => p.Type == PaDataType.PA_FOR_USER);
                        var decodedUsers = KrbPaForUser.Decode(users.Value);

                        Console.WriteLine("{0}       - {1} :", decrypted, users.Type);
                        Console.WriteLine("{0}          - UserName :", decrypted);
                        Console.WriteLine("{0}             - Type :  {1}", decrypted, decodedUsers.UserName.Type);
                        Console.WriteLine("{0}             - Name :  {1}", decrypted, decodedUsers.UserName.Name[0]);
                        Console.WriteLine("{0}          - UserRealm :  {1}", decrypted, decodedUsers.UserRealm);
                        Console.WriteLine("{0}          - AuthPackage :  {1}", decrypted, decodedUsers.AuthPackage);
                        Console.WriteLine("{0}          - Checksum :", decrypted);
                        Console.WriteLine("{0}             - Type :  {1}", decrypted, decodedUsers.Checksum.Type);
                        Console.WriteLine("{0}             - Checksum :  {1}", decrypted, (BitConverter.ToString(decodedUsers.Checksum.Checksum.ToArray())).Replace("-", ""));
                    }
                    else if (data.Type == PaDataType.PA_TGS_REQ)
                    {
                        var tgsreq = paData.FirstOrDefault(p => p.Type == PaDataType.PA_TGS_REQ);
                        var apreq = tgsreq.DecodeApReq();
                        Console.WriteLine("       - {0} :", tgsreq.Type);
                        //Console.WriteLine("          - Value :  {0}", (BitConverter.ToString(tgsreq.Value.ToArray())).Replace("-", ""));
                        Console.WriteLine("          - {0} :", apreq.MessageType);
                        Console.WriteLine("             - pvno :  {0}", apreq.ProtocolVersionNumber);
                        Console.WriteLine("             - ApOptions :  {0}", apreq.ApOptions);
                        Console.WriteLine("             - Ticket :");
                        Console.WriteLine("                - tkt-vno :  {0}", apreq.Ticket.TicketNumber);
                        Console.WriteLine("                - Realm :  {0}", apreq.Ticket.Realm);
                        Console.WriteLine("                - SName : ");
                        Console.WriteLine("                   - Type :  {0}", apreq.Ticket.SName.Type);
                        foreach (var name in apreq.Ticket.SName.Name)
                        {
                            Console.WriteLine("                   - Name :  {0}", name);
                        }

                        Console.WriteLine("                - EncryptedPart :");
                        Console.WriteLine("                   - kvno :  {0}", apreq.Ticket.EncryptedPart.KeyVersionNumber);
                        Console.WriteLine("                   - EType :  {0}", apreq.Ticket.EncryptedPart.EType);
                        Console.WriteLine("                   - Cipher :  [krbtgtEncryptedCipher...]");
                        //Console.WriteLine("                   - Cipher :  {0}", (BitConverter.ToString(apreq.Ticket.EncryptedPart.Cipher.ToArray())).Replace("-", ""));
                        Console.WriteLine("             - Authenticator : ");
                        Console.WriteLine("                - kvno :  {0}", apreq.Authenticator.KeyVersionNumber);
                        Console.WriteLine("                - EType :  {0}", apreq.Authenticator.EType);
                        //Console.WriteLine("                - Cipher :  {0}", apreq.Authenticator.Cipher);
                        var authenticator = apreq.Authenticator.Decrypt(sessionKey,
                            KeyUsage.PaTgsReqAuthenticator,
                            d => KrbAuthenticator.DecodeApplication(d));

                        Console.WriteLine("                - Realm :  {0}", authenticator.Realm);
                        Console.WriteLine("                - SequenceNumber :  {0}", authenticator.SequenceNumber);
                        Console.WriteLine("                - Subkey :");
                        Console.WriteLine("                   - EType :  {0}", authenticator.Subkey.EType);
                        Console.WriteLine("                   - KeyValue :  {0}", (BitConverter.ToString(authenticator.Subkey.KeyValue.ToArray())).Replace("-", ""));
                        Console.WriteLine("                - CTime :  {0}", authenticator.CTime);
                        Console.WriteLine("                - CuSec :  {0}", authenticator.CuSec);
                        Console.WriteLine("                - CName :  ");
                        Console.WriteLine("                   - Type :  {0}", authenticator.CName.Type);
                        Console.WriteLine("                   - Name :  {0}", authenticator.CName.Name);
                        Console.WriteLine("                - Checksum :");
                        Console.WriteLine("                   - Type :  {0}", authenticator.Checksum.Type);
                        Console.WriteLine("                   - Checksum :  {0}", (BitConverter.ToString(authenticator.Checksum.Checksum.ToArray())).Replace("-", ""));

                        //if (authenticator.Checksum.Type == ChecksumType.KERB_CHECKSUM_HMAC_MD5)
                        //{
                        //    Console.WriteLine("======================================");
                        //    Console.WriteLine("Testing... ");
                        //    Console.WriteLine(authenticator.Checksum.DecodeDelegation().Flags);
                        //    Console.WriteLine(authenticator.Checksum.DecodeDelegation().ChannelBinding);
                        //    Console.WriteLine(authenticator.Checksum.DecodeDelegation().Extensions);
                        //    Console.WriteLine(authenticator.Checksum.DecodeDelegation().DelegationOption);
                        //    Console.WriteLine(authenticator.Checksum.DecodeDelegation().DelegationTicket);
                        //    Console.WriteLine("======================================");
                        //}


                        Console.WriteLine("                - AuthorizationData :  {0}", authenticator.AuthorizationData);
                        Console.WriteLine("                - AuthenticatorVersionNumber :  {0}", authenticator.AuthenticatorVersionNumber);
                    }
                    else
                    {
                        Console.WriteLine("[-] Unknown PaData Type: {0}", data.Type);
                    }
                }
            }




        }



        //AS-REQ
        public static void PrintReq(KrbAsReq reqMessage, KerberosKey key)
        {
            Console.WriteLine("    * MessageType :  {0}", reqMessage.MessageType);
            Console.WriteLine("    * pvno :  {0}", reqMessage.ProtocolVersionNumber);
            Console.WriteLine("    * PaData :");
            PrintPaData(reqMessage.PaData, key);
            Console.WriteLine("    * Body :");
            Console.WriteLine("       - KdcOptions :  {0}", reqMessage.Body.KdcOptions);
            Console.WriteLine("       - CName :");
            Console.WriteLine("          - Type :  {0}", reqMessage.Body.CName.Type);
            Console.WriteLine("          - Name :  {0}", reqMessage.Body.CName.Name);
            Console.WriteLine("       - Realm :  {0}", reqMessage.Body.Realm);
            Console.WriteLine("       - SName :");
            Console.WriteLine("          - Type :  {0}", reqMessage.Body.SName.Type);
            for (int i = 0; i < reqMessage.Body.SName.Name.Count(); i++)
            {
                Console.WriteLine("          - Name :  {0}", reqMessage.Body.SName.Name[i]);
            }
            Console.WriteLine("       - Till :  {0}", reqMessage.Body.Till);
            Console.WriteLine("       - RTime :  {0}", reqMessage.Body.RTime);
            Console.WriteLine("       - Nonce :  {0}", reqMessage.Body.Nonce);
            Console.WriteLine("       - EType :");
            for (int i = 0; i < reqMessage.Body.EType.Count(); i++)
            {
                Console.WriteLine("          - EncType :  {0}", reqMessage.Body.EType[i]);
            }
            Console.WriteLine("       - Addresses :");
            Console.WriteLine("          - Type :  {0}", reqMessage.Body.Addresses[0].AddressType);
            var addrhex = BitConverter.ToString(reqMessage.Body.Addresses[0].Address.ToArray());
            var addr = string.Join("", Regex.Split(addrhex, "-").Select(x => (char)Convert.ToByte(x, 16)));
            Console.WriteLine("          - Addresses :  {0}", addr);
            Console.WriteLine("       - AdditionalTickets :  {0}", reqMessage.Body.AdditionalTickets);
            Console.WriteLine("       - EncAuthorizationData :  {0}", reqMessage.Body.EncAuthorizationData);
            Console.WriteLine("       - From :  {0}", reqMessage.Body.From);
        }

        //TGS-REQ
        public static void PrintReq(KrbTgsReq reqMessage, KerberosKey key, KerberosKey sessionKey = null)
        {
            Console.WriteLine("    * MessageType :  {0}", reqMessage.MessageType);
            Console.WriteLine("    * pvno :  {0}", reqMessage.ProtocolVersionNumber);
            Console.WriteLine("    * PaData :");
            PrintPaData(reqMessage.PaData, key, "", sessionKey);
            Console.WriteLine("    * Body :");
            Console.WriteLine("       - KdcOptions :  {0}", reqMessage.Body.KdcOptions);
            //Console.WriteLine("       - CName :");
            //Console.WriteLine("          - Type :  {0}", reqMessage.Body.CName.Type);
            //Console.WriteLine("          - Name :  {0}", reqMessage.Body.CName.Name);
            Console.WriteLine("       - Realm :  {0}", reqMessage.Body.Realm);
            Console.WriteLine("       - SName :");
            Console.WriteLine("          - Type :  {0}", reqMessage.Body.SName.Type);
            for (int i = 0; i < reqMessage.Body.SName.Name.Count(); i++)
            {
                Console.WriteLine("          - Name :  {0}", reqMessage.Body.SName.Name[i]);
            }
            Console.WriteLine("       - Till :  {0}", reqMessage.Body.Till);
            Console.WriteLine("       - RTime :  {0}", reqMessage.Body.RTime);
            Console.WriteLine("       - Nonce :  {0}", reqMessage.Body.Nonce);
            Console.WriteLine("       - EType :");
            for (int i = 0; i < reqMessage.Body.EType.Count(); i++)
            {
                Console.WriteLine("          - EncType :  {0}", reqMessage.Body.EType[i]);
            }
            //Console.WriteLine("       - Addresses :");
            //Console.WriteLine("          - Type :  {0}", reqMessage.Body.Addresses);

            Console.WriteLine("       - EncAuthorizationData :  {0}", reqMessage.Body.EncAuthorizationData);
            Console.WriteLine("       - From :  {0}", reqMessage.Body.From);

            Console.Write("       - AdditionalTickets : ");
            if (reqMessage.Body.AdditionalTickets != null)
            {
                Console.WriteLine("(S4U2Self Ticket)");
                foreach (var ticket in reqMessage.Body.AdditionalTickets)
                {
                    Console.WriteLine("          - tkt-vno :  {0}", ticket.TicketNumber);
                    Console.WriteLine("          - Realm :  {0}", ticket.Realm);
                    Console.WriteLine("          - SName : ");
                    Console.WriteLine("             - Name :  {0}", ticket.SName.Name);
                    Console.WriteLine("             - Type :  {0}", ticket.SName.Type);
                    Console.WriteLine("          - EncryptedPart :");
                    Console.WriteLine("             - kvno :  {0}", ticket.EncryptedPart.KeyVersionNumber);
                    Console.WriteLine("             - EType :  {0}", ticket.EncryptedPart.EType);
                    //Console.WriteLine("          - Cipher :  {0}", (BitConverter.ToString(asRep.Ticket.EncryptedPart.Cipher.ToArray())).Replace("-", ""));
                    Console.WriteLine("             - Cipher :  [ServiceEncryptedCipher...]");
                }
            }
            else
            {
                Console.WriteLine();
            }


        }


        public static void PrintReq(KrbKdcReq reqMessage, KerberosKey key)
        {
            Console.WriteLine("    * MessageType :  {0}", reqMessage.MessageType);
            Console.WriteLine("    * pvno :  {0}", reqMessage.ProtocolVersionNumber);
            Console.WriteLine("    * PaData :");
            PrintPaData(reqMessage.PaData, key);
            Console.WriteLine("    * Body :");
            Console.WriteLine("       - KdcOptions :  {0}", reqMessage.Body.KdcOptions);
            //Console.WriteLine("       - Realm :  {0}", reqMessage.Body.Realm);
            //Console.WriteLine("       - SName :");
            //Console.WriteLine("          - Type :  {0}", reqMessage.Body.SName.Type);
            //for (int i = 0; i < reqMessage.Body.SName.Name.Count(); i++)
            //{
            //    Console.WriteLine("          - Name :  {0}", reqMessage.Body.SName.Name[i]);
            //}
            //Console.WriteLine("       - Till :  {0}", reqMessage.Body.Till);
            //Console.WriteLine("       - RTime :  {0}", reqMessage.Body.RTime);
            //Console.WriteLine("       - Nonce :  {0}", reqMessage.Body.Nonce);
            //Console.WriteLine("       - EType :  {0}", reqMessage.Body.Nonce);
            //Console.WriteLine("       - EType :");
            //for (int i = 0; i < reqMessage.Body.EType.Count(); i++)
            //{
            //    Console.WriteLine("          - EncType :  {0}", reqMessage.Body.EType[i]);
            //}
            ////Console.WriteLine("       - Addresses :");
            ////Console.WriteLine("          - Type :  {0}", reqMessage.Body.Addresses);
            //Console.WriteLine("       - AdditionalTickets :  {0}", reqMessage.Body.AdditionalTickets);
            //Console.WriteLine("       - EncAuthorizationData :  {0}", reqMessage.Body.EncAuthorizationData);
        }



        //AS-REP
        public static void PrintRep(KrbAsRep asRep, KerberosKey key)
        {
            Console.WriteLine("    * MessageType :  {0}", asRep.MessageType);
            Console.WriteLine("    * pvno :  {0}", asRep.ProtocolVersionNumber);
            Console.WriteLine("    * PaData :");
            PrintPaData(asRep.PaData, key);


            Console.WriteLine("    * CRealm :  {0}", asRep.CRealm);
            Console.WriteLine("    * CName : ");
            Console.WriteLine("       - Type :  {0}", asRep.CName.Type);
            Console.WriteLine("       - Name :  {0}", asRep.CName.Name);
            Console.WriteLine("    * Ticket :");
            Console.WriteLine("       - tkt-vno :  {0}", asRep.Ticket.TicketNumber);
            Console.WriteLine("       - Realm :  {0}", asRep.Ticket.Realm);
            Console.WriteLine("       - SName : ");
            Console.WriteLine("          - Name :  {0}", asRep.Ticket.SName.Name);
            Console.WriteLine("          - Type :  {0}", asRep.Ticket.SName.Type);
            Console.WriteLine("       - EncryptedPart :");
            Console.WriteLine("          - kvno :  {0}", asRep.Ticket.EncryptedPart.KeyVersionNumber);
            Console.WriteLine("          - EType :  {0}", asRep.Ticket.EncryptedPart.EType);
            //Console.WriteLine("          - Cipher :  {0}", (BitConverter.ToString(asRep.Ticket.EncryptedPart.Cipher.ToArray())).Replace("-", ""));
            Console.WriteLine("          - Cipher :  [krbtgtEncryptedCipher...]");
            Console.WriteLine("    * Enc-Part :");
            Console.WriteLine("       - kvno :  {0}", asRep.EncPart.KeyVersionNumber);
            Console.WriteLine("       - EType :  {0}", asRep.EncPart.EType);
            //Console.WriteLine("       - Cipher :  {0}", (BitConverter.ToString(asRep.EncPart.Cipher.ToArray())).Replace("-", ""));
            Console.WriteLine("       - Cipher :  [ClientEncryptedCipher...]");
        }

        //TGS-REP
        public static void PrintRep(KrbTgsRep tgsRep, KerberosKey key)
        {
            Console.WriteLine("    * MessageType :  {0}", tgsRep.MessageType);
            Console.WriteLine("    * pvno :  {0}", tgsRep.ProtocolVersionNumber);
            Console.WriteLine("    * PaData :");
            PrintPaData(tgsRep.PaData, key);
            Console.WriteLine("    * CRealm :  {0}", tgsRep.CRealm);
            Console.WriteLine("    * CName :");
            Console.WriteLine("       - Type :  {0}", tgsRep.CName.Type);
            Console.WriteLine("       - Name :  {0}", tgsRep.CName.Name);
            Console.WriteLine("    * Ticket :");
            Console.WriteLine("       - tkt-vno :  {0}", tgsRep.Ticket.TicketNumber);
            Console.WriteLine("       - Realm :  {0}", tgsRep.Ticket.Realm);
            Console.WriteLine("       - SName : ");
            Console.WriteLine("          - Name :  {0}", tgsRep.Ticket.SName.Name);
            Console.WriteLine("          - Type :  {0}", tgsRep.Ticket.SName.Type);
            Console.WriteLine("       - EncryptedPart :");
            Console.WriteLine("          - kvno :  {0}", tgsRep.Ticket.EncryptedPart.KeyVersionNumber);
            Console.WriteLine("          - EType :  {0}", tgsRep.Ticket.EncryptedPart.EType);
            if (tgsRep.Ticket.SName.Name[0] == "krbtgt")
            {
                Console.WriteLine("          - Cipher :  [krbtgtEncryptedCipher...]");
            }
            else
            {
                Console.WriteLine("          - Cipher :  [ServiceEncryptedCipher...]");
            }

            //Console.WriteLine("          - Cipher :  {0}", (BitConverter.ToString(tgsRep.Ticket.EncryptedPart.Cipher.ToArray())).Replace("-", ""));
            Console.WriteLine("    * Enc-Part :");
            Console.WriteLine("       - EType :  {0}", tgsRep.EncPart.EType);
            Console.WriteLine("       - kvno :  {0}", tgsRep.EncPart.KeyVersionNumber);
            //Console.WriteLine("       - Cipher :  {0}", (BitConverter.ToString(tgsRep.EncPart.Cipher.ToArray())).Replace("-", ""));
            Console.WriteLine("       - Cipher :  [SubSessionKeyEncryptedCipher..]");
        }

        //AS-REP ENC-PART
        public static void PrintRepEnc(KrbEncAsRepPart repMessage, KerberosKey key)
        {
            Console.WriteLine("       - AuthTime :  {0}", repMessage.AuthTime);
            Console.WriteLine("       - StartTime :  {0}", repMessage.StartTime);
            Console.WriteLine("       - EndTime :  {0}", repMessage.EndTime);
            Console.WriteLine("       - RenewTill :  {0}", repMessage.RenewTill);
            Console.WriteLine("       - Nonce :  {0}", repMessage.Nonce);
            Console.WriteLine("       - Realm :  {0}", repMessage.Realm);
            Console.WriteLine("       - SName :");
            Console.WriteLine("          - Type :  {0}", repMessage.SName.Type);
            for (int i = 0; i < repMessage.SName.Name.Count(); i++)
            {
                Console.WriteLine("          - Name :  {0}", repMessage.SName.Name[i]);
            }
            Console.WriteLine("       - EncryptedPaData :");
            PrintPaData(repMessage.EncryptedPaData.MethodData, key, "   ", null);
            Console.WriteLine("       - Key :");
            Console.WriteLine("          - EType :  {0}", repMessage.Key.EType);
            Console.WriteLine("          - Value :  {0}", (BitConverter.ToString(repMessage.Key.KeyValue.ToArray())).Replace("-", ""));
            Console.WriteLine("       - KeyExpiration :  {0}", repMessage.KeyExpiration);
            Console.WriteLine("       - CAddr :");
            Console.WriteLine("          - Type :  {0}", repMessage.CAddr[0].AddressType);
            var addrhex = BitConverter.ToString(repMessage.CAddr[0].Address.ToArray());
            var addr = string.Join("", Regex.Split(addrhex, "-").Select(x => (char)Convert.ToByte(x, 16)));
            Console.WriteLine("          - Addresses :  {0}", addr);
            Console.WriteLine("       - Flags :  {0}", repMessage.Flags);
            Console.WriteLine("       - LastReq ");
            Console.WriteLine("          - Type :  {0}", repMessage.LastReq.FirstOrDefault().Type);
            Console.WriteLine("          - Type :  {0}", repMessage.LastReq.FirstOrDefault().Value);

        }

        //TGS-REP ENC-PART
        public static void PrintRepEnc(KrbEncTgsRepPart repMessage, KerberosKey key)
        {
            Console.WriteLine("       - AuthTime :  {0}", repMessage.AuthTime);
            Console.WriteLine("       - StartTime :  {0}", repMessage.StartTime);
            Console.WriteLine("       - EndTime :  {0}", repMessage.EndTime);
            Console.WriteLine("       - RenewTill :  {0}", repMessage.RenewTill);
            Console.WriteLine("       - Nonce :  {0}", repMessage.Nonce);
            Console.WriteLine("       - Realm :  {0}", repMessage.Realm);
            Console.WriteLine("       - SName :");
            Console.WriteLine("          - Type :  {0}", repMessage.SName.Type);
            for (int i = 0; i < repMessage.SName.Name.Count(); i++)
            {
                Console.WriteLine("          - Name :  {0}", repMessage.SName.Name[i]);
            }
            Console.WriteLine("       - EncryptedPaData :");
            if (repMessage.EncryptedPaData != null)
            {
                PrintPaData(repMessage.EncryptedPaData.MethodData, key, "   ");
            }
            Console.WriteLine("       - Key :");
            Console.WriteLine("          - EType :  {0}", repMessage.Key.EType);
            Console.WriteLine("          - Value :  {0}", (BitConverter.ToString(repMessage.Key.KeyValue.ToArray())).Replace("-", ""));
            Console.WriteLine("       - KeyExpiration :  {0}", repMessage.KeyExpiration);
            //Console.WriteLine("       - CAddr :  {0}", repMessage.CAddr);
            //Console.WriteLine("          - Type :  {0}", repMessage.CAddr[0].AddressType);
            //var addrhex = BitConverter.ToString(repMessage.CAddr[0].Address.ToArray());
            //var addr = string.Join("", Regex.Split(addrhex, "-").Select(x => (char)Convert.ToByte(x, 16)));
            //Console.WriteLine("          - Addresses :  {0}", addr);
            Console.WriteLine("       - Flags :  {0}", repMessage.Flags);
            Console.WriteLine("       - LastReq ");
            Console.WriteLine("          - Type :  {0}", repMessage.LastReq.FirstOrDefault().Type);
            Console.WriteLine("          - Type :  {0}", repMessage.LastReq.FirstOrDefault().Value);

        }

        //TICKET ENC-PART
        public static void PrintTicketEnc(KrbEncTicketPart ticketEnc)
        {
            Console.WriteLine("       - AuthTime :  {0}", ticketEnc.AuthTime);
            Console.WriteLine("       - StartTime :  {0}", ticketEnc.StartTime);
            Console.WriteLine("       - EndTime :  {0}", ticketEnc.EndTime);
            Console.WriteLine("       - RenewTill :  {0}", ticketEnc.RenewTill);
            Console.WriteLine("       - CRealm :  {0}", ticketEnc.CRealm);
            Console.WriteLine("       - CName :");
            Console.WriteLine("          - Type :  {0}", ticketEnc.CName.Type);
            Console.WriteLine("          - Name :  {0}", ticketEnc.CName.Name);
            Console.WriteLine("       - AuthorizationData :");

            if (ticketEnc.AuthorizationData != null)
            {
                foreach (var data in ticketEnc.AuthorizationData)
                {
                    if (data.Type == AuthorizationDataType.AdIfRelevant)
                    {
                        Console.WriteLine("          - Type :  {0}", ticketEnc.AuthorizationData.FirstOrDefault().Type);

                        var decodedData = data.DecodeAdIfRelevant();

                        foreach (var data2 in decodedData)
                        {
                            if (data2.Type == AuthorizationDataType.AdWin2kPac)
                            {
                                Console.WriteLine("             - Type :  {0}", data2.Type);
                                PrintPAC(data2);
                            }
                            else
                            {
                                Console.WriteLine("[-] Unknown AdIfRelevant Data Type :  {0}", data2.Type);
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine("[-] Unknown Authorization Data sType :  {0}", data.Type);
                    }
                }
            }
            //CAddr Temp
            string caddr = null;
            if (ticketEnc.CAddr != null)
            {
                caddr = ticketEnc.CAddr.ToString();
            }
            Console.WriteLine("       - CAddr :  {0}", caddr);
            Console.WriteLine("       - Flags :  {0}", ticketEnc.Flags);
            Console.WriteLine("       - Key :");
            Console.WriteLine("          - EType :  {0}", ticketEnc.Key.EType);
            Console.WriteLine("          - Value :  {0}", (BitConverter.ToString(ticketEnc.Key.KeyValue.ToArray())).Replace("-", ""));
            Console.WriteLine("       - Transited :");
            Console.WriteLine("          - Type :  {0}", ticketEnc.Transited.Type);
            Console.WriteLine("          - Contents :  {0}", BitConverter.ToString(ticketEnc.Transited.Contents.ToArray()));
        }


        public static void PrintPAC(KrbAuthorizationData authData)
        {
            var pac = new PrivilegedAttributeCertificate(authData);
            //Type
            Console.WriteLine("                - Type :  {0}", pac.Type);
            //Version
            Console.WriteLine("                - Version :  {0}", pac.Version);

            //LogonInfo
            if (pac.LogonInfo != null)
            {
                Console.WriteLine("                - LogonInfo :  ");
                Console.WriteLine("                   - PacType :  ", pac.LogonInfo.PacType);
                Console.WriteLine("                   - DomainId :  ");
                if (pac.LogonInfo.DomainId != null) 
                {
                    Console.WriteLine("                      - Revision :  {0}", pac.LogonInfo.DomainId.Revision);
                    Console.WriteLine("                      - IdentifierAuthority :  {0}", pac.LogonInfo.DomainId.IdentifierAuthority.Authority);
                    Console.WriteLine("                      - SubAuthority :  {0}", String.Join(", ", pac.LogonInfo.DomainId.SubAuthority.ToArray()));
                    Console.WriteLine("                      - SubAuthorityCount :  {0}", pac.LogonInfo.DomainId.SubAuthorityCount);
                }
                Console.WriteLine("                   - ExtraIds :  ");
                if (pac.LogonInfo.ExtraIds != null)
                {
                    foreach (var extraId in pac.LogonInfo.ExtraIds.ToArray())
                    {
                        Console.WriteLine("                      - Attributes :  {0}", extraId.Attributes);
                        Console.WriteLine("                      - Sid :  {0}", extraId.Sid);
                        Console.WriteLine("                      - Revision :  {0}", extraId.Sid.Revision);
                        Console.WriteLine("                      - IdentifierAuthority :  {0}", extraId.Sid.IdentifierAuthority.Authority);
                        //Console.WriteLine("                      - IdentifierAuthority :  {0}", BitConverter.ToString(extraId.Sid.IdentifierAuthority.IdentifierAuthority.ToArray()));
                        Console.WriteLine("                      - SubAuthority :  {0}", String.Join(", ", extraId.Sid.SubAuthority.ToArray()));
                        Console.WriteLine("                      - SubAuthorityCount :  {0}", extraId.Sid.SubAuthorityCount);
                    }
                }
               
                
                Console.WriteLine("                   - DomainSid :  ");
                Console.WriteLine("                      - Attributes :  {0}", pac.LogonInfo.DomainSid.Attributes);
                Console.WriteLine("                      - Id :  {0}", pac.LogonInfo.DomainSid.Id);
                Console.WriteLine("                      - Value :  {0}", pac.LogonInfo.DomainSid.Value);
                Console.WriteLine("                   - ExtraSidCount :  {0}", pac.LogonInfo.ExtraSidCount);
                Console.WriteLine("                   - ExtraSids :  ");
                if (pac.LogonInfo.ExtraSids != null)
                {
                    foreach (var extraSid in pac.LogonInfo.ExtraSids.ToArray())
                    {
                        Console.WriteLine("                      - Id :  {0}", extraSid.Id);
                        Console.WriteLine("                      - Attributes :  {0}", extraSid.Attributes);
                        Console.WriteLine("                      - Value :  {0}", extraSid.Value);
                    }
                }
                

                Console.WriteLine("                   - GroupCount :  {0}", pac.LogonInfo.GroupCount);
                Console.WriteLine("                   - GroupId :  {0}", pac.LogonInfo.GroupId);
                Console.WriteLine("                   - GroupIds :  ");
                if (pac.LogonInfo.GroupIds != null)
                {
                    foreach (var groupId in pac.LogonInfo.GroupIds)
                    {
                        Console.WriteLine("                      - RelativeId :  {0}", groupId.RelativeId);
                        Console.WriteLine("                      - Attributes :  {0}", groupId.Attributes);
                    }
                }
                
                
                Console.WriteLine("                   - GroupSid :  {0}", pac.LogonInfo.GroupSid);
                Console.WriteLine("                   - GroupSids :  ");
                if (pac.LogonInfo.GroupSids != null)
                {
                    foreach (var groupSid in pac.LogonInfo.GroupSids)
                    {
                        Console.WriteLine("                      - Id :  {0}", groupSid.Id);
                        Console.WriteLine("                      - Attributes :  {0}", groupSid.Attributes);
                        Console.WriteLine("                      - Value :  {0}", groupSid.Value);
                    }
                }
                
                
                Console.WriteLine("                   - HomeDirectory :  {0}", pac.LogonInfo.HomeDirectory);
                Console.WriteLine("                   - HomeDrive :  {0}", pac.LogonInfo.HomeDrive);
                Console.WriteLine("                   - KickOffTime :  {0}", pac.LogonInfo.KickOffTime);
                Console.WriteLine("                   - LastFailedILogon :  {0}", pac.LogonInfo.LastFailedILogon);
                Console.WriteLine("                   - LastSuccessfulILogon :  {0}", pac.LogonInfo.LastSuccessfulILogon);
                Console.WriteLine("                   - LogoffTime :  {0}", pac.LogonInfo.LogoffTime);
                Console.WriteLine("                   - LogonCount :  {0}", pac.LogonInfo.LogonCount);
                Console.WriteLine("                   - LogonScript :  {0}", pac.LogonInfo.LogonScript);
                Console.WriteLine("                   - LogonTime :  {0}", pac.LogonInfo.LogonTime);
                Console.WriteLine("                   - ProfilePath :  {0}", pac.LogonInfo.ProfilePath);
                Console.WriteLine("                   - PwdCanChangeTime :  {0}", pac.LogonInfo.PwdCanChangeTime);
                Console.WriteLine("                   - PwdLastChangeTime :  {0}", pac.LogonInfo.PwdLastChangeTime);
                Console.WriteLine("                   - PwdMustChangeTime :  {0}", pac.LogonInfo.PwdMustChangeTime);
                Console.WriteLine("                   - Reserved1 :  {0}", String.Join(", ", pac.LogonInfo.Reserved1.ToArray().Select(x=> x.ToString())));
                Console.WriteLine("                   - Reserved3 :  {0}", pac.LogonInfo.Reserved3);
                Console.WriteLine("                   - ResourceDomainId :  {0}", pac.LogonInfo.ResourceDomainId);
                Console.WriteLine("                   - ResourceDomainSid :  {0}", pac.LogonInfo.ResourceDomainSid);
                Console.WriteLine("                   - ResourceGroupCount :  {0}", pac.LogonInfo.ResourceGroupCount);
                Console.WriteLine("                   - ResourceGroupIds :  {0}", pac.LogonInfo.ResourceGroupIds);

                Console.WriteLine("                   - ResourceGroups : ");
                if (pac.LogonInfo.ResourceGroups != null)
                {
                    foreach (var resourceGroup in pac.LogonInfo.ResourceGroups)
                    {
                        Console.WriteLine("                      - Attributes :  {0}", resourceGroup.Attributes);
                        Console.WriteLine("                      - Id :  {0}", resourceGroup.Id);
                        Console.WriteLine("                      - Value :  {0}", resourceGroup.Value);
                    }
                }
               

                
                Console.WriteLine("                   - SubAuthStatus :  {0}", pac.LogonInfo.SubAuthStatus);
                Console.WriteLine("                   - UserAccountControl :  {0}", pac.LogonInfo.UserAccountControl);
                Console.WriteLine("                   - UserDisplayName :  {0}", pac.LogonInfo.UserDisplayName);
                Console.WriteLine("                   - UserFlags :  {0}", pac.LogonInfo.UserFlags);
                Console.WriteLine("                   - UserId :  {0}", pac.LogonInfo.UserId);
                Console.WriteLine("                   - UserName :  {0}", pac.LogonInfo.UserName);
                Console.WriteLine("                   - UserSessionKey :  {0}", (BitConverter.ToString(pac.LogonInfo.UserSessionKey.ToArray())).Replace("-",""));
                Console.WriteLine("                   - UserSid :  {0}", pac.LogonInfo.UserSid);
                Console.WriteLine("                   - DomainName :  {0}", pac.LogonInfo.DomainName);
                Console.WriteLine("                   - ServerName :  {0}", pac.LogonInfo.ServerName);
                Console.WriteLine("                   - BadPasswordCount :  {0}", pac.LogonInfo.BadPasswordCount);
                Console.WriteLine("                   - FailedILogonCount :  {0}", pac.LogonInfo.FailedILogonCount);
                
            }
            



            //DelegationInformation
            if (pac.DelegationInformation != null)
            {
                Console.WriteLine("                - {0} :  ", pac.DelegationInformation.PacType);
                Console.WriteLine("                   - S4U2ProxyTarget :  {0}", pac.DelegationInformation.S4U2ProxyTarget.Buffer);
                Console.WriteLine("                   - S4UTransitedServices :  {0}", pac.DelegationInformation.S4UTransitedServices);
            }



            //ClientInformation
            if (pac.ClientInformation != null)
            {
                Console.WriteLine("                - ClientInformation :  ");
                Console.WriteLine("                   - PacType :  {0}", pac.ClientInformation.PacType);
                Console.WriteLine("                   - ClientId :  {0}", pac.ClientInformation.ClientId);
                Console.WriteLine("                   - Name :  {0}", pac.ClientInformation.Name);
                Console.WriteLine("                   - NameLength :  {0}", pac.ClientInformation.NameLength);
            }



            //KdcSignature
            if (pac.KdcSignature != null)
            {
                Console.WriteLine("                - KdcSignature :  ");
                Console.WriteLine("                   - PacType :  {0}", pac.KdcSignature.PacType);
                Console.WriteLine("                   - RODCIdentifier :  {0}", pac.KdcSignature.RODCIdentifier);
                Console.WriteLine("                   - Signature :  {0}", (BitConverter.ToString(pac.KdcSignature.Signature.ToArray())).Replace("-", ""));
                Console.WriteLine("                   - SignatureData :  [...]" );//pac.KdcSignature.SignatureData);
                Console.WriteLine("                   - Type :  {0}", pac.KdcSignature.Type);
                Console.WriteLine("                   - Validated :  {0}", pac.KdcSignature.Validated);
                Console.WriteLine("                   - Validator :  ");
                Console.WriteLine("                      - Validator :  {0}", pac.KdcSignature.Validator.Usage);
                Console.WriteLine("                      - Validator :  {0}", (BitConverter.ToString(pac.KdcSignature.Validator.Signature.ToArray())).Replace("-",""));
            }


            //ServerSignature
            if (pac.ServerSignature != null)
            {
                Console.WriteLine("                - ServerSignature :  ");
                Console.WriteLine("                   - PacType :  {0}", pac.ServerSignature.PacType);
                Console.WriteLine("                   - RODCIdentifier :  {0}", pac.ServerSignature.RODCIdentifier);
                Console.WriteLine("                   - Signature :  {0}", (BitConverter.ToString(pac.ServerSignature.Signature.ToArray())).Replace("-", ""));
                Console.WriteLine("                   - SignatureData :  [...]");//pac.ServerSignature.SignatureData);
                Console.WriteLine("                   - Type :  {0}", pac.ServerSignature.Type);
                Console.WriteLine("                   - Validated :  {0}", pac.ServerSignature.Validated);
                Console.WriteLine("                   - Validator :  ");
                Console.WriteLine("                      - Validator :  {0}", pac.ServerSignature.Validator.Usage);
                Console.WriteLine("                      - Validator :  {0}", (BitConverter.ToString(pac.ServerSignature.Validator.Signature.ToArray())).Replace("-", ""));
            }



            //ClientClaims
            if (pac.ClientClaims != null)
            {
                Console.WriteLine("                - ClientClaims :  ");
                Console.WriteLine("                   - PacType :  {0}", pac.ClientClaims.PacType);
                Console.WriteLine("                   - ClaimSetSize :  {0}", pac.ClientClaims.ClaimSetSize);
                Console.WriteLine("                   - ClaimsSet :  {0}", pac.ClientClaims.ClaimsSet);
                Console.WriteLine("                   - CompressionFormat :  {0}", pac.ClientClaims.CompressionFormat);
                Console.WriteLine("                   - ReservedField :  {0}", pac.ClientClaims.ReservedField);
                Console.WriteLine("                   - ReservedFieldSize :  {0}", pac.ClientClaims.ReservedFieldSize);
                Console.WriteLine("                   - ReservedType :  {0}", pac.ClientClaims.ReservedType);
                Console.WriteLine("                   - UncompressedClaimSetSize :  {0}", pac.ClientClaims.UncompressedClaimSetSize);
            }


            //CredentialType
            if (pac.CredentialType != null)
            {
                Console.WriteLine("                - CredentialType :  ");
                Console.WriteLine("                   - PacType :  {0}", pac.CredentialType.PacType);
                Console.WriteLine("                   - EncryptionType :  {0}", pac.CredentialType.EncryptionType);
                Console.WriteLine("                   - SerializedData :  {0}", pac.CredentialType.SerializedData);
                Console.WriteLine("                   - Version :  {0}", pac.CredentialType.Version);
            }


            //DeviceClaims
            if (pac.DeviceClaims != null)
            {
                Console.WriteLine("                - DeviceClaims :  ");
                Console.WriteLine("                   - PacType :  {0}", pac.DeviceClaims.PacType);
                Console.WriteLine("                   - ReservedType :  {0}", pac.DeviceClaims.ReservedType);
                Console.WriteLine("                   - ReservedField :  {0}", pac.DeviceClaims.ReservedField);
                Console.WriteLine("                   - ReservedFieldSize :  {0}", pac.DeviceClaims.ReservedFieldSize);
                Console.WriteLine("                   - UncompressedClaimSetSize :  {0}", pac.DeviceClaims.UncompressedClaimSetSize);
            }



            //UpnDomainInformation
            if (pac.UpnDomainInformation != null)
            {
                Console.WriteLine("                - UpnDomainInformation :  ");
                Console.WriteLine("                   - PacType :  {0}", pac.UpnDomainInformation.PacType);
                Console.WriteLine("                   - Upn :  {0}", pac.UpnDomainInformation.Upn);
                Console.WriteLine("                   - UpnLength :  {0}", pac.UpnDomainInformation.UpnLength);
                Console.WriteLine("                   - UpnOffset :  {0}", pac.UpnDomainInformation.UpnOffset);
                Console.WriteLine("                   - Domain :  {0}", pac.UpnDomainInformation.Domain);
                Console.WriteLine("                   - DnsDomainNameLength :  {0}", pac.UpnDomainInformation.DnsDomainNameLength);
                Console.WriteLine("                   - DnsDomainNameOffset :  {0}", pac.UpnDomainInformation.DnsDomainNameOffset);
            }




            
            //DecodingErrors
            if (pac.DecodingErrors != null)
            {
                Console.WriteLine("                - DecodingErrors :  ");
                foreach (var decodingError in pac.DecodingErrors)
                {
                    Console.WriteLine("                   - Type :  {0}", decodingError.Type);
                    Console.WriteLine("                   - Exception :  {0}", decodingError.Exception);
                    Console.WriteLine("                   - Data :  {0}", decodingError.Data);
                }

            }
            //HasRequiredFields
            Console.WriteLine("                - HasRequiredFields :  {0}", pac.HasRequiredFields);


        }




        public static void PrintKirbi(string kirbiString)
        {
            byte[] kirbiBytes = Convert.FromBase64String(kirbiString);


            //KRB-CRED         ::= [APPLICATION 22]   SEQUENCE {
            //pvno[0]                INTEGER,
            //msg - type[1]            INTEGER, --KRB_CRED
            //tickets[2]             SEQUENCE OF Ticket,
            //enc - part[3]            EncryptedData
            //}
            var myCred = KrbCred.DecodeApplication(kirbiBytes.AsMemory());
            Console.WriteLine("    * {0}", myCred.MessageType);
            Console.WriteLine("    * pvno :  {0}", myCred.ProtocolVersionNumber);
            Console.WriteLine("    * Tickets :  {0}", myCred.Tickets[0]);



            //EncKrbCredPart   ::= [APPLICATION 29]   SEQUENCE {
            //ticket-info[0]         SEQUENCE OF KrbCredInfo,
            //nonce[1]               INTEGER OPTIONAL,
            //timestamp[2]           KerberosTime OPTIONAL,
            //usec[3]                INTEGER OPTIONAL,
            //s-address[4]           HostAddress OPTIONAL,
            //r-address[5]           HostAddress OPTIONAL
            //}
            var encryptedData = myCred.EncryptedPart;
            var encCredPart = KrbEncKrbCredPart.DecodeApplication(encryptedData.Cipher);

            Console.WriteLine("    * Encrypted Data :  ");
            Console.WriteLine("       - Timestamp :  {0}", encCredPart.Timestamp);
            Console.WriteLine("       - USec :  {0}", encCredPart.USec);
            Console.WriteLine("       - SAddress : ");
            if (encCredPart.SAddress != null)
            {
                Console.WriteLine("          - AddressType :  {0}", encCredPart.SAddress.AddressType);
                Console.WriteLine("          - Address :  {0}", encCredPart.SAddress.Address);
            }
            Console.WriteLine("       - RAddress :  ");
            if (encCredPart.RAddress != null)
            {
                Console.WriteLine("          - AddressType :  {0}", encCredPart.RAddress.AddressType);
                Console.WriteLine("          - Address :  {0}", encCredPart.RAddress.Address);
            }
            Console.WriteLine("       - Nonce :  {0}", encCredPart.Nonce);


            //KrbCredInfo::= SEQUENCE {
            //                key[0]                 EncryptionKey,
            //prealm[1]              Realm OPTIONAL,
            //pname[2]               PrincipalName OPTIONAL,
            //flags[3]               TicketFlags OPTIONAL,
            //authtime[4]            KerberosTime OPTIONAL,
            //starttime[5]           KerberosTime OPTIONAL,
            //endtime[6]             KerberosTime OPTIONAL
            //renew - till[7]          KerberosTime OPTIONAL,
            //srealm[8]              Realm OPTIONAL,
            //sname[9]               PrincipalName OPTIONAL,
            //caddr[10]              HostAddresses OPTIONAL
            //}
            Console.WriteLine("       - Ticket Info : ");
            var ticketInfo = encCredPart.TicketInfo;
            foreach (var info in ticketInfo)
            {
                Console.WriteLine("          - Realm :  {0}", info.Realm);
                Console.WriteLine("          - PName :  ");
                Console.WriteLine("             - Type :  {0}", info.PName.Type);
                Console.WriteLine("             - Name :  {0}", info.PName.Name);
                Console.WriteLine("          - Flags :  {0}", info.Flags);
                Console.WriteLine("          - AuthTime :  {0}", info.AuthTime);
                Console.WriteLine("          - StartTime :  {0}", info.StartTime);
                Console.WriteLine("          - EndTime :  {0}", info.EndTime);
                Console.WriteLine("          - RenewTill :  {0}", info.RenewTill);
                Console.WriteLine("          - SRealm :  {0}", info.SRealm);
                Console.WriteLine("          - SName :  ");
                Console.WriteLine("             - Type :  {0}", info.SName.Type);
                Console.WriteLine("             - Name :  {0}", info.SName.Name);
                Console.WriteLine("          - Key : ");
                Console.WriteLine("             - EType :  {0}", info.Key.EType);
                Console.WriteLine("             - KeyValue :  {0}", (BitConverter.ToString(info.Key.KeyValue.ToArray())).Replace("-", ""));
            }

        }


    }
}
