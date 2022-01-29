using System;
using System.IO;
using System.Text.RegularExpressions;

namespace KerberosRun
{
    public static class Utils
    {
        public enum PrincipalNameType
        {
            NT_UNKNOWN = 0,
            NT_PRINCIPAL = 1,
            NT_SRV_INST = 2,
            NT_SRV_HST = 3,
            NT_SRV_XHST = 4,
            NT_UID = 5,
            NT_X500_PRINCIPAL = 6,
            NT_SMTP_NAME = 7,
            NT_ENTERPRISE = 10,
            NT_MS_PRINCIPAL = -128
        }

        // From: https://stackoverflow.com/questions/2972103/how-to-convert-a-string-to-a-hex-byte-array
        public static byte[] ToHexByteArray(String HexString)
        {
            int NumberChars = HexString.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(HexString.Substring(i, 2), 16);
            }
            return bytes;
        }

        public static byte[] StringToByteArray(string str)
        {
            System.Text.ASCIIEncoding enc = new System.Text.ASCIIEncoding();
            return enc.GetBytes(str);
        }

        public static string ByteArrayToString(byte[] arr)
        {
            System.Text.ASCIIEncoding enc = new System.Text.ASCIIEncoding();
            return enc.GetString(arr);
        }


        //https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/Helpers.cs#L46
        public static bool IsBase64String(string s)
        {
            s = s.Trim();
            return (s.Length % 4 == 0) && Regex.IsMatch(s, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
        }


        public static string MakeTicketFileName(string username, string[] sname = null)
        {
            string name;
            if (sname == null)
            {
                name = $"{DateTime.Now:yyyyMMddHHmmss}_" + username + "_TGT.kirbi";
            }
            else
            {
                name = $"{DateTime.Now:yyyyMMddHHmmss}_" + username + "_" + sname[0] + "@" + sname[1] + "_TGS.kirbi";
            }
            return name;
        }

        //https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/Helpers.cs#L311
        static public bool WriteBytesToFile(string filename, byte[] data, bool overwrite = false)
        {
            bool result = true;
            string filePath = Path.GetFullPath(filename);

            try
            {
                if (!overwrite)
                {
                    if (File.Exists(filePath))
                    {
                        throw new Exception(String.Format("{0} already exists! Data not written to file.\r\n", filePath));
                    }
                }
                File.WriteAllBytes(filePath, data);
                Console.WriteLine("[+] Ticket is written to {0}", filePath);
            }
            catch (Exception e)
            {
                Console.WriteLine("\r\nException: {0}", e.Message);
                result = false;
            }

            return result;
        }
    }
}
