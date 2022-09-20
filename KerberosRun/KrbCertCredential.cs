using System;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace KerberosRun
{
    //Adapted from Kerberos.Net Source
    public class KrbCertCredential : KerberosCredential, IDisposable
    {
        private DateTime now = DateTime.Now;

        private static readonly Oid IdPkInitAuthData = new Oid("1.3.6.1.5.2.3.1");
        private static readonly Oid DiffieHellman = new Oid("1.2.840.10046.2.1");

        private ReadOnlyMemory<byte> clientDHNonce;
        private IKeyAgreement agreement = CryptoPal.Platform.DiffieHellmanModp14();


        public KrbCertCredential(
            X509Certificate2 cert,
            string username = null,
            string domain = null
        )
        {
            if (cert == null)
            {
                throw new ArgumentException("Certificate cannot be null", nameof(cert));
            }

            if (!cert.HasPrivateKey)
            {
                throw new InvalidOperationException("Certificate must have a private key");
            }

            if (string.IsNullOrWhiteSpace(username))
            {
                username = TryExtractPrincipalName(cert);
            }

            TrySplitUserNameDomain(username, out username, ref domain);

            this.Certificate = cert;

            this.UserName = username;

            if (!string.IsNullOrWhiteSpace(domain))
            {
                this.Domain = domain.ToUpperInvariant();
            }
        }

        public static bool CanPrompt { get; set; } = Environment.UserInteractive;

        public X509Certificate2 Certificate { get; }

        public override bool SupportsOptimisticPreAuthentication => this.Certificate != null;

        public X509IncludeOption IncludeOption { get; set; } = X509IncludeOption.ExcludeRoot;

        public KeyAgreementAlgorithm KeyAgreement { get; set; } = KeyAgreementAlgorithm.DiffieHellmanModp14;

        public bool SupportsEllipticCurveDiffieHellman { get; set; } = false;

        public bool SupportsDiffieHellman { get; set; } = true;

 

        //protected virtual IKeyAgreement StartKeyAgreement()
        //{
        //    // We should try and pick smart defaults based on what we know if it's set to none

        //    if (this.KeyAgreement == KeyAgreementAlgorithm.None)
        //    {
        //        if (this.SupportsEllipticCurveDiffieHellman)
        //        {
        //            this.KeyAgreement = KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256;
        //        }
        //        else if (this.SupportsDiffieHellman)
        //        {
        //            this.KeyAgreement = KeyAgreementAlgorithm.DiffieHellmanModp14;
        //        }
        //    }

        //    // if neither EC nor DH are enabled then KeyAgreement still equals None
        //    // None will fall through to null which is validated in TransformKdcReq

        //    switch (this.KeyAgreement)
        //    {
        //        case KeyAgreementAlgorithm.DiffieHellmanModp2 when this.SupportsDiffieHellman:
        //            return CryptoPal.Platform.DiffieHellmanModp2();

        //        case KeyAgreementAlgorithm.DiffieHellmanModp14 when this.SupportsDiffieHellman:
        //            return CryptoPal.Platform.DiffieHellmanModp14();

        //        case KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256 when this.SupportsEllipticCurveDiffieHellman:
        //            return CryptoPal.Platform.DiffieHellmanP256();

        //        case KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP384 when this.SupportsEllipticCurveDiffieHellman:
        //            return CryptoPal.Platform.DiffieHellmanP384();

        //        case KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP521 when this.SupportsEllipticCurveDiffieHellman:
        //            return CryptoPal.Platform.DiffieHellmanP521();
        //    }

        //    return null;
        //}

        public static KerberosCredential Get(string query, string realmHint) => Get(
            query,
            realmHint,
            StoreName.My.ToString(),
            StoreLocation.CurrentUser
        );

        public static KerberosCredential Get(string query, string realmHint, string storeName, StoreLocation location)
        {
            var store = new X509Store(storeName, location);

            try
            {
                store.Open(OpenFlags.ReadOnly);

                foreach (var cert in store.Certificates)
                {
                    if (string.Equals(query, cert.GetNameInfo(X509NameType.UpnName, false), StringComparison.InvariantCultureIgnoreCase) ||
                        string.Equals(query, cert.GetNameInfo(X509NameType.DnsName, false), StringComparison.InvariantCultureIgnoreCase) ||
                        string.Equals(query, cert.GetNameInfo(X509NameType.DnsFromAlternativeName, false), StringComparison.InvariantCultureIgnoreCase) ||
                        string.Equals(query, cert.GetNameInfo(X509NameType.SimpleName, false), StringComparison.InvariantCultureIgnoreCase))
                    {
                        return new KerberosAsymmetricCredential(cert, query, realmHint);
                    }
                    else if (string.Equals(query, cert.Thumbprint, StringComparison.InvariantCultureIgnoreCase))
                    {
                        return new KerberosAsymmetricCredential(cert, domain: realmHint);
                    }
                }

                return null;
            }
            finally
            {
                store.Close();
            }
        }


        protected virtual bool CacheKeyAgreementParameters(IKeyAgreement agreement) => false;




        private static Exception OnlyKeyAgreementSupportedException() => throw new NotSupportedException("Only key agreement is supported for PKINIT authentication");


        internal KrbAuthPack CreateDiffieHellmanAuthPack(KrbKdcReqBody body)
        {
            using (var sha1 = CryptoPal.Platform.Sha1())
            {
                var encoded = body.Encode();

                var paChecksum = sha1.ComputeHash(encoded.Span);

                var parametersAreCached = this.CacheKeyAgreementParameters(this.agreement);

                var domainParams = KrbDH.FromKeyAgreement(agreement);

                var transformer = CryptoService.CreateTransform(EncryptionType.AES256_CTS_HMAC_SHA1_96);

                this.clientDHNonce = transformer.GenerateRandomBytes(agreement.PublicKey.KeyLength);

                var authPack = new KrbAuthPack
                {
                    PKAuthenticator = new KrbPKAuthenticator
                    {
                        Nonce = body.Nonce,
                        PaChecksum = paChecksum
                    },
                    ClientPublicValue = new KrbSubjectPublicKeyInfo
                    {
                        Algorithm = new KrbAlgorithmIdentifier
                        {
                            Algorithm = DiffieHellman,
                            Parameters = domainParams.EncodeSpecial()
                        },
                        SubjectPublicKey = this.agreement.PublicKey.EncodePublicKey()
                    },
                    ClientDHNonce = this.clientDHNonce
                };

                return authPack;
            }
        }

        private static ReadOnlyMemory<byte> GenerateNonce(EncryptionType encryptionType, int minSize)
        {
            var transformer = CryptoService.CreateTransform(encryptionType);

            return transformer.GenerateRandomBytes(minSize);
        }


        public override T DecryptKdcRep<T>(KrbKdcRep kdcRep, KeyUsage keyUsage, Func<ReadOnlyMemory<byte>, T> func)
        {
            var paPkRep = kdcRep?.PaData?.FirstOrDefault(a => a.Type == PaDataType.PA_PK_AS_REP);

            var pkRep = KrbPaPkAsRep.Decode(paPkRep.Value);

            if (pkRep.DHInfo != null)
            {
                this.sharedSecret = this.DeriveDHKeyAgreement(kdcRep, pkRep, out this.sharedSecretEType);
            }
            else
            {
                throw OnlyKeyAgreementSupportedException();
            }

            return base.DecryptKdcRep(kdcRep, keyUsage, func);
        }

        private ReadOnlyMemory<byte> DeriveDHKeyAgreement(KrbKdcRep kdcRep, KrbPaPkAsRep pkRep, out EncryptionType etype)
        {
            var dhKeyInfo = this.ValidateDHReply(pkRep);

            var kdcPublicKey = DiffieHellmanKey.ParsePublicKey(dhKeyInfo.SubjectPublicKey, this.agreement.PublicKey.KeyLength);

            this.agreement.ImportPartnerKey(kdcPublicKey);

            var derivedKey = this.agreement.GenerateAgreement();

            ReadOnlySpan<byte> serverDHNonce = default;

            if (pkRep.DHInfo.ServerDHNonce.HasValue)
            {
                serverDHNonce = pkRep.DHInfo.ServerDHNonce.Value.Span;
            }

            var transform = CryptoService.CreateTransform(kdcRep.EncPart.EType);

            etype = kdcRep.EncPart.EType;

            return PKInitString2Key.String2Key(derivedKey.Span, transform.KeySize, this.clientDHNonce.Span, serverDHNonce);
        }

        private EncryptionType sharedSecretEType;
        private ReadOnlyMemory<byte> sharedSecret;
        private bool disposedValue;

        private KrbKdcDHKeyInfo ValidateDHReply(KrbPaPkAsRep pkRep)
        {
            var signed = new SignedCms();

            signed.Decode(pkRep.DHInfo.DHSignedData.ToArray());

            //Don't verify
            //this.VerifyKdcSignature(signed);

            return KrbKdcDHKeyInfo.Decode(signed.ContentInfo.Content);
        }

        protected virtual void VerifyKdcSignature(SignedCms signedMessage)
        {
            if (signedMessage == null)
            {
                throw new ArgumentNullException(nameof(signedMessage));
            }

            signedMessage.CheckSignature(verifySignatureOnly: false);
        }

        private static string TryExtractPrincipalName(X509Certificate2 cert)
        {
            var nameInfo = cert.GetNameInfo(X509NameType.UpnName, false);

            if (nameInfo != null)
            {
                return nameInfo;
            }

            return cert.Subject;
        }

        public override void Validate()
        {
            base.Validate();

            if (this.Certificate.PrivateKey == null)
            {
                throw new InvalidOperationException("A Private Key must be set");
            }

            if (this.Certificate.PublicKey == null)
            {
                throw new InvalidOperationException("A Public Key must be set");
            }
        }


        public override KerberosKey CreateKey()
        {
            return new KerberosKey(key: this.sharedSecret.ToArray(), etype: this.sharedSecretEType);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposedValue)
            {
                if (disposing)
                {
                    this.agreement?.Dispose();
                }

                this.disposedValue = true;
            }
        }

        public void Dispose()
        {
            this.Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }


    public class KrbDH : KrbDiffieHellmanDomainParameters
    {
        internal static ReadOnlyMemory<byte> DepadRight(ReadOnlyMemory<byte> data)
        {
            var result = data;

            for (var i = data.Length - 1; i > 0; i--)
            {
                if (data.Span[i] == 0)
                {
                    result = result.Slice(0, i);
                }
                else
                {
                    break;
                }
            }

            return result;
        }

        internal static ReadOnlyMemory<byte> PadLeft(ReadOnlyMemory<byte> pv)
        {
            if (pv.Span[0] != 0)
            {
                var copy = new Memory<byte>(new byte[pv.Length + 1]);

                pv.CopyTo(copy.Slice(1));

                pv = copy;
            }

            return pv;
        }

        internal static KrbDiffieHellmanDomainParameters FromKeyAgreement(IKeyAgreement agreement)
        {
            if (!(agreement.PublicKey is DiffieHellmanKey pk))
            {
                throw new ArgumentException("Not a DH key agreement");
            }

            return new KrbDiffieHellmanDomainParameters
            {
                P = PadLeft(pk.Modulus),
                G = DepadRight(pk.Generator),
                Q = pk.Factor
            };
        }
    }
}
