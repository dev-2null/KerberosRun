using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Ndr;

namespace KerberosRun
{

    public class PacCredentialData : INdrStruct
    {
        public void Marshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            buffer.WriteInt32LittleEndian(this.CredentialCount);

            //Not sure about this
            buffer.WriteDeferredStructArray(this.SuppCredential);

        }

        public void Unmarshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            this.CredentialCount = buffer.ReadInt32LittleEndian();

            this.SuppCredential = buffer.ReadConformantArray<SupplementalCredential>(this.CredentialCount, new Func<SupplementalCredential>(buffer.ReadStruct<SupplementalCredential>));
        }


        public PacCredentialData(ReadOnlyMemory<byte> bytes)
        {
            using (var buffer = new NdrBuffer(bytes))
            {
                buffer.UnmarshalObject(this);
            }
        }


        [KerberosIgnore]
        public int CredentialCount { get; set; }
        public IEnumerable<SupplementalCredential> SuppCredential { get; set; }

        public PacCredentialData(int CredentialCount, SupplementalCredential[] Credentials)
        {
            this.CredentialCount = CredentialCount;
            this.SuppCredential = Credentials;
        }

 
    }


    public class SupplementalCredential : INdrStruct
    {
        public SupplementalCredential() { }
        public void Marshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            buffer.WriteStruct<RpcString>(this.PackageName);

            buffer.WriteInt32LittleEndian(this.CredentialSize);

            buffer.WriteDeferredConformantArray<sbyte>(this.Credentials.ToArray());
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            this.PackageName = buffer.ReadStruct<RpcString>();

            this.CredentialSize = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredConformantArray<sbyte>(this.CredentialSize, v => this.Credentials = v);
        }


        [KerberosIgnore]
        public RpcString PackageName { get; set; }
        public int CredentialSize { get; set; }

        public ReadOnlyMemory<sbyte> Credentials;
        public SupplementalCredential(RpcString PackageName, int CredentialSize, sbyte[] Credentials)
        {
            this.PackageName = PackageName;
            this.CredentialSize = CredentialSize;
            this.Credentials = Credentials;
        }
    }

}
