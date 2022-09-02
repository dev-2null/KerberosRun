using Kerberos.NET.Credentials;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using NLog;
using System;
using System.Threading.Tasks;

namespace KerberosRun
{
    public abstract class KerberosService
    {
        protected Logger logger;
        protected readonly KrbTcp transport;
        internal KerberosCredential cred;
        protected byte[] bKirbi;
        internal readonly DateTime now;
        internal KrbTicket ticket;
        public bool requestFailed = false;

        public KerberosService()
        {
            logger = LogManager.GetCurrentClassLogger();
            now = DateTime.Now;
            transport = new KrbTcp(null);
            cred = Helper.GetCredFromOption();
        }
        public abstract Task Ask();
        public abstract void Create();
        public string ToKirbi()
        {
            return Convert.ToBase64String(bKirbi);
        }
        public void DisplayTicket()
        {
            logger.Info($"[*] Ticket: {string.Join("/", ticket.SName.Name)}");
            Console.WriteLine($"    {ToKirbi()}");
        }
        public abstract void ToFile();
        public abstract void Display();
    }


}
