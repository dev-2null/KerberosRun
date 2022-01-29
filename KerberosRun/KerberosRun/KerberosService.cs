using Kerberos.NET.Credentials;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KerberosRun
{
    public abstract class KerberosService
    {
        protected Logger logger;
        protected readonly TcpKerberosTransport transport;
        protected KerberosCredential cred;
        protected byte[] bKirbi;
        internal readonly DateTime now;
        internal KrbTicket ticket;
        
        public KerberosService()
        {
            logger = LogManager.GetCurrentClassLogger();
            now = DateTime.Now;
            transport = new TcpKerberosTransport(null);
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
            logger.Info($"[*] Ticket");
            Console.WriteLine($"    {ToKirbi()}");
        }
        public abstract void ToFile();
        public abstract void Display();
    }


}
