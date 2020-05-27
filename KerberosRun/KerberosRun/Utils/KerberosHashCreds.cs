using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;

namespace KerberosRun.Utils
{
    public class KerberosHashCreds : KerberosCredential
    {
        private readonly string hash;
        private readonly EncryptionType etype;

        public KerberosHashCreds(string username, string hash, EncryptionType etype, string domain = null)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new ArgumentException("UserName cannot be null", nameof(username));
            }

            if (string.IsNullOrWhiteSpace(hash))
            {
                throw new ArgumentException("Hash cannot be null", nameof(hash));
            }

            TrySplitUserNameDomain(username, out username, ref domain);

            UserName = username;
            this.hash = hash;
            this.etype = etype;

            if (!string.IsNullOrWhiteSpace(domain))
            {
                Domain = domain.ToUpperInvariant();
            }
        }
        public override bool SupportsOptimisticPreAuthentication => false;


        public override KerberosKey CreateKey()
        {
            var principalName = new PrincipalName(PrincipalNameType.NT_PRINCIPAL, Domain, new[] { UserName });

            Byte[] hashbytes = Utils.ToHexByteArray(this.hash);
            var salt = "";
            return new KerberosKey(
                hashbytes,
                null,
                principalName,
                etype: this.etype,
                saltType: SaltType.ActiveDirectoryUser,
                salt: salt
            );
        }
    }
}
