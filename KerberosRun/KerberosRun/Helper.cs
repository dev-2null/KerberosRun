using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KerberosRun
{
    public static class Helper
    {
        public static KerberosCredential GetCredFromOption()
        {
            if (Options.Instance.User == null) { return null; }
            KerberosCredential cred;
            string hash = null;
            EncryptionType eType = EncryptionType.RC4_HMAC_NT;

            if (Options.Instance.RC4 != null) { eType = EncryptionType.RC4_HMAC_NT; hash = Options.Instance.RC4; }
            else if (Options.Instance.AES128 != null) { eType = EncryptionType.AES128_CTS_HMAC_SHA1_96; hash = Options.Instance.AES128; }
            if (Options.Instance.AES256 != null) { eType = EncryptionType.AES256_CTS_HMAC_SHA1_96; hash = Options.Instance.AES256; }


            if (hash == null)
            { cred = new KerberosPasswordCredential(Options.Instance.User, Options.Instance.Password, Options.Instance.Domain); }
            else
            { cred = new KerberosHashCreds(Options.Instance.User, hash, eType, Options.Instance.Domain); }

            return cred;
        }
    }
}
