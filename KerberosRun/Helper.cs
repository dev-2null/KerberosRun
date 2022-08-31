using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;

using Kerberos.NET.Client;


namespace KerberosRun
{
    public static class Helper
    {
        public static KerberosCredential GetCredFromOption()
        {
            if (KerberosRun.User == null) { return null; }
            KerberosCredential cred;

            if (KerberosRun.UserHash == null)
            { cred = new KerberosPasswordCredential(KerberosRun.User, KerberosRun.Pass, KerberosRun.Domain); }
            else
            { cred = new KerberosHashCreds(KerberosRun.User, KerberosRun.UserHash, KerberosRun.UserEType, KerberosRun.Domain); }

            //var client = new KerberosClient();
            //var c = new KerberosPasswordCredential(KerberosRun.User, KerberosRun.Pass, KerberosRun.Domain);
            //client.Authenticate(c).Wait();
            //client.GetServiceTicket(KerberosRun.SPN).Wait();
            //System.Console.ReadLine();
            return cred;
        }
    }
}
