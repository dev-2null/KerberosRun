using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KerberosRun
{
    public class KerberosRun
    {
        public static EncryptionType decryptEtype;
        public Options options;
        public static bool Verbose;
        public static string Ticket;


        public KerberosRun(Options opts)
        {
            options = opts;
            if (options.Domain == null) { Options.GetHelp(); Environment.Exit(1); }
            Verbose = options.Verbose;
            Ticket = options.Ticket;

            if (options.DecryptTGS != null || options.DecryptTGT != null)
            {
                switch (options.DecryptEtype.Trim().ToLower())
                {
                    case "rc4":
                        decryptEtype = EncryptionType.RC4_HMAC_NT;
                        break;
                    case "aes128":
                        decryptEtype = EncryptionType.AES128_CTS_HMAC_SHA1_96;
                        break;
                    default:
                        decryptEtype = EncryptionType.AES256_CTS_HMAC_SHA1_96;
                        break;
                }
            }
        }

        public async Task ResolveCommandAsync()
        {
            if (options.AskTGT)
            {
                await GetTGT();
            }
            else if (options.AskTGS)
            {
                await GetTGS();
            }
            else if (options.S4U2Self)
            {
                await GetS4U2Self();
            }
            else if (options.S4U)
            {
                await GetS4U2Proxy();
            }
        }

        public async Task<TGT> GetTGT()
        {
            var tgt = new TGT();
            await tgt.Ask();
            tgt.Display();
            tgt.DisplayTicket();
            return tgt;
        }

        public async Task GetTGS()
        {
            TGS tgs;
            if (Ticket == null)
            {
                var tgt = GetTGT().Result;
                tgs = new TGS(tgt);
            }
            else
            {
                tgs = new TGS(Ticket);
            }

            await tgs.Ask();
            tgs.Display();
            tgs.DisplayTicket();
        }


        public async Task<S4U2Self> GetS4U2Self(TGT tgt = null)
        {
            S4U2Self self;
            if (Ticket == null && tgt == null)
            {
                tgt = GetTGT().Result;
                self = new S4U2Self(tgt);
            }
            else if (tgt != null)
            {
                self = new S4U2Self(tgt);
            }
            else
            {
                self = new S4U2Self(Ticket);
            }
            await self.Ask();
            self.Display();
            self.DisplayTicket();
            return self;
        }


        public async Task GetS4U2Proxy()
        {
            S4U2Proxy proxy;
            if (Ticket == null)
            {
                var tgt = GetTGT().Result;
                var self = GetS4U2Self(tgt).Result;
                proxy = new S4U2Proxy(tgt, self.s4u2selfTicket);
            }
            else
            {
                var self = GetS4U2Self().Result;
                proxy = new S4U2Proxy(Ticket, self.s4u2selfTicket);

            }
            await proxy.Ask();
            proxy.Display();
            proxy.DisplayTicket();
        }

    }
}
