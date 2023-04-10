using System;
using Kerberos.NET.Entities;
using System.Security.Cryptography.Pkcs;
using Kerberos.NET;
using System.Linq;
using System.Security.Cryptography;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.IO;
using System.Collections.Generic;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Client;
using System.Security.Cryptography.X509Certificates;

namespace KerberosRun
{
    public static class Helper
    {
        public static KerberosCredential GetCredFromOption()
        {
            if (KerberosRun.User == "") { return null; }
            KerberosCredential cred;

            if (KerberosRun.Cert != null)
            {
                if (Utils.IsBase64String(KerberosRun.Cert))
                {
                    KerberosRun.Certificate = new X509Certificate2(Convert.FromBase64String(KerberosRun.Cert), KerberosRun.CertPass);
                }
                else
                {
                    KerberosRun.Certificate = new X509Certificate2(KerberosRun.Cert, KerberosRun.CertPass);
                }
                cred = new KrbCertCredential(KerberosRun.Certificate, KerberosRun.User, KerberosRun.Domain);
                cred.Domain = KerberosRun.Domain;

            }
            else if (KerberosRun.UserHash != null)
            {
                cred = new KerberosHashCreds(KerberosRun.User, KerberosRun.UserHash, KerberosRun.UserEType, KerberosRun.Domain); 
            }
            else 
            { 
                cred = new KerberosPasswordCredential(KerberosRun.User, KerberosRun.Pass, KerberosRun.Domain); 
            }

            //var client = new KerberosClient();
            //var c = new KerberosPasswordCredential(KerberosRun.User, KerberosRun.Pass, KerberosRun.Domain);
            //client.Authenticate(c).Wait();
            //client.GetServiceTicket(KerberosRun.SPN).Wait();
            //System.Console.ReadLine();
            return cred;
        }


        public static KerberosCredential GetCredFromOptionForTarget()
        {
            if (KerberosRun.TargetService == "") { return null; }
            KerberosCredential cred;

            if (KerberosRun.UserHash != null)
            {
                cred = new KerberosHashCreds(KerberosRun.TargetService, KerberosRun.UserHash, KerberosRun.UserEType, KerberosRun.TargetDomain);
            }
            else
            {
                cred = new KerberosPasswordCredential(KerberosRun.TargetService, KerberosRun.Pass, KerberosRun.TargetDomain);
            }

            return cred;
        }


        // From Rubeus
        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2235-L2262
        public static byte[] KerberosDecrypt(EncryptionType eType, int keyUsage, byte[] key, byte[] data)
        {
            Interop.KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;

            // locate the crypto system
            int status = Interop.CDLocateCSystem(eType, out pCSystemPtr);
            pCSystem = (Interop.KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0)
                throw new Win32Exception(status, "Error on CDLocateCSystem");

            // initialize everything
            IntPtr pContext;
            Interop.KERB_ECRYPT_Initialize pCSystemInitialize = (Interop.KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(pCSystem.Initialize, typeof(Interop.KERB_ECRYPT_Initialize));
            Interop.KERB_ECRYPT_Decrypt pCSystemDecrypt = (Interop.KERB_ECRYPT_Decrypt)Marshal.GetDelegateForFunctionPointer(pCSystem.Decrypt, typeof(Interop.KERB_ECRYPT_Decrypt));
            Interop.KERB_ECRYPT_Finish pCSystemFinish = (Interop.KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(pCSystem.Finish, typeof(Interop.KERB_ECRYPT_Finish));
            status = pCSystemInitialize(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Win32Exception(status);

            int outputSize = data.Length;
            if (data.Length % pCSystem.BlockSize != 0)
                outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);

            string algName = Marshal.PtrToStringAuto(pCSystem.AlgName);

            outputSize += pCSystem.Size;
            byte[] output = new byte[outputSize];

            // actually perform the decryption
            status = pCSystemDecrypt(pContext, data, data.Length, output, ref outputSize);
            pCSystemFinish(ref pContext);

            return output.Take(outputSize).ToArray();
        }


        public static byte[] KerberosEncrypt(EncryptionType eType, int keyUsage, byte[] key, byte[] data)
        {
            Interop.KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;

            // locate the crypto system
            int status = Interop.CDLocateCSystem(eType, out pCSystemPtr);
            pCSystem = (Interop.KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0)
                throw new Win32Exception(status, "Error on CDLocateCSystem");

            // initialize everything
            IntPtr pContext;
            Interop.KERB_ECRYPT_Initialize pCSystemInitialize = (Interop.KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(pCSystem.Initialize, typeof(Interop.KERB_ECRYPT_Initialize));
            Interop.KERB_ECRYPT_Encrypt pCSystemEncrypt = (Interop.KERB_ECRYPT_Encrypt)Marshal.GetDelegateForFunctionPointer(pCSystem.Encrypt, typeof(Interop.KERB_ECRYPT_Encrypt));
            Interop.KERB_ECRYPT_Finish pCSystemFinish = (Interop.KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(pCSystem.Finish, typeof(Interop.KERB_ECRYPT_Finish));
            status = pCSystemInitialize(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Win32Exception(status);

            int outputSize = data.Length;
            if (data.Length % pCSystem.BlockSize != 0)
                outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);

            string algName = Marshal.PtrToStringAuto(pCSystem.AlgName);

            outputSize += pCSystem.Size;
            byte[] output = new byte[outputSize];

            // actually perform the decryption
            status = pCSystemEncrypt(pContext, data, data.Length, output, ref outputSize);
            pCSystemFinish(ref pContext);

            return output;
        }

        public static PrivilegedAttributeCertificate GetPAC(KrbEncTicketPart ticketEnc)
        {
            if (ticketEnc.AuthorizationData != null)
            {
                foreach (var authData in ticketEnc.AuthorizationData)
                {
                    if (authData.Type == AuthorizationDataType.AdIfRelevant)
                    {
    
                        var decodedData = authData.DecodeAdIfRelevant();

                        foreach (var data in decodedData)
                        {
                            if (data.Type == AuthorizationDataType.AdWin2kPac)
                            {
                                return new PrivilegedAttributeCertificate(data);
                            }

                        }
                    }
                }
            }
            return null;
        }

    }



}
