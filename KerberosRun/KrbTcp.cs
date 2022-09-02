using Kerberos.NET.Dns;
using Kerberos.NET.Transport;
using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Kerberos.NET.Client;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Buffers.Binary;
using System.Buffers;
using NLog;

namespace KerberosRun
{
    public class KrbTcp : TcpKerberosTransport
    {
        private Logger logger = LogManager.GetCurrentClassLogger();
        public KrbTcp(ILoggerFactory logger) : base(logger) { }


        public override async Task<T> SendMessage<T>(
    string target,
    ReadOnlyMemory<byte> encoded,
    CancellationToken cancellation = default
)
        {
            try
            {
                using (var client = await GetClient(target).ConfigureAwait(false))
                {
                    if (!client.Connected)
                    {
                        logger.Error("[x] Unable to connect to {0}\n", target);
                        Environment.Exit(1);
                    }
                    var stream = client.GetStream();

                    await WriteMessage(encoded, stream, cancellation).ConfigureAwait(false);

                    return await ReadResponse<T>(stream, cancellation, this.ReceiveTimeout).ConfigureAwait(false);
                }
            }
            catch (SocketException sx)
            {
                throw new KerberosTransportException("TCP Connect failed", sx);
            }
        }




        private async Task<ITcpSocket> GetClient(string target)
        {
            var attempts = this.MaximumAttempts;
            SocketException lastThrown = null;

            do
            {
                var client = new TcpSocket();

                bool connected = false;

                try
                {
                    connected = await client.ConnectDC(target, ConnectTimeout).ConfigureAwait(false);

                    if (client != null)
                    {
                        connected = true;
                    }
                }
                catch (SocketException ex)
                {
                    lastThrown = ex;
                }

                if (!connected)
                {

                    lastThrown = lastThrown ?? new SocketException((int)SocketError.TimedOut);

                    continue;
                }

                client.SendTimeout = this.SendTimeout;
                client.ReceiveTimeout = this.ReceiveTimeout;

                return client;
            }
            while (--attempts > 0);

            return null;
        }


        private static async Task<T> ReadResponse<T>(NetworkStream stream, CancellationToken cancellation, TimeSpan readTimeout)
    where T : Kerberos.NET.Asn1.IAsn1ApplicationEncoder<T>, new()
        {
            using (var messageSizeBytesRented = CryptoPool.Rent<byte>(4))
            {
                var messageSizeBytes = messageSizeBytesRented.Memory.Slice(0, 4);

                await ReadFromStream(messageSizeBytes, stream, cancellation, readTimeout).ConfigureAwait(false);

                var messageSize = BinaryPrimitives.ReadInt32BigEndian(messageSizeBytes.Span);

                var response = await ReadFromStream(messageSize, stream, cancellation, readTimeout).ConfigureAwait(false);

                return Decode<T>(response);
            }
        }

        private static async Task WriteMessage(ReadOnlyMemory<byte> encoded, NetworkStream stream, CancellationToken cancellation)
        {
            var length = encoded.Length + 4;

            using (var messageRented = CryptoPool.Rent<byte>(length))
            {
                var message = messageRented.Memory.Slice(0, length);

                FormatKerberosMessageStream(encoded, message);

                if (!MemoryMarshal.TryGetArray(message, out ArraySegment<byte> segment))
                {
                    segment = new ArraySegment<byte>(message.ToArray());
                }

                await stream.WriteAsync(segment.Array, 0, message.Length, cancellation).ConfigureAwait(false);
            }
        }


        public static void FormatKerberosMessageStream(ReadOnlyMemory<byte> message, Memory<byte> formattedMessage)
        {
            BinaryPrimitives.WriteInt32BigEndian(formattedMessage.Span.Slice(0, 4), message.Length);

            message.CopyTo(formattedMessage.Slice(4));
        }

        public static async Task ReadFromStream(Memory<byte> readResponse, NetworkStream stream, CancellationToken cancellation, TimeSpan readTimeout)
        {
            if (!MemoryMarshal.TryGetArray(readResponse, out ArraySegment<byte> segment))
            {
                throw new InvalidOperationException("Cannot get backing array");
            }

            using (var timeout = new CancellationTokenSource(readTimeout))
            using (var cancel = CancellationTokenSource.CreateLinkedTokenSource(cancellation, timeout.Token))
            {
                int read = 0;

                while (read < readResponse.Length)
                {
                    read += await stream.ReadAsync(
                        segment.Array,
                        read,
                        readResponse.Length - read,
                        cancel.Token
                    ).ConfigureAwait(false);
                }
            }
        }

        public static async Task<ReadOnlyMemory<byte>> ReadFromStream(
    int messageSize,
    NetworkStream stream,
    CancellationToken cancellation,
    TimeSpan readTimeout
)
        {
            var bytes = new byte[messageSize];

            await ReadFromStream(bytes, stream, cancellation, readTimeout);

            return bytes;
        }

    }



    internal class TcpSocket : ITcpSocket
    {
        private readonly TcpClient client;

        public string TargetName { get; private set; }

        public TimeSpan ReceiveTimeout
        {
            get => TimeSpan.FromMilliseconds(this.client.ReceiveTimeout);
            set => this.client.ReceiveTimeout = (int)value.TotalMilliseconds;
        }

        public TimeSpan SendTimeout
        {
            get => TimeSpan.FromMilliseconds(this.client.SendTimeout);
            set => this.client.SendTimeout = (int)value.TotalMilliseconds;
        }

        public bool Connected => this.client.Connected;

        public DateTimeOffset LastRelease { get; private set; }

        public TcpSocket()
        {

            this.client = new TcpClient(AddressFamily.InterNetwork)
            {
                NoDelay = true,
                LingerState = new LingerOption(false, 0)
            };
        }

        Task<bool> ITcpSocket.Connect(DnsRecord target, TimeSpan connectTimeout)
        {
            throw new NotImplementedException();
        }

        public async Task<bool> ConnectDC(string target, TimeSpan connectTimeout)
        {
            var tcs = new TaskCompletionSource<bool>();

            using (var cts = new CancellationTokenSource(connectTimeout))
            {
                var connectTask = this.client.ConnectAsync(target, 88);

                using (cts.Token.Register(() => tcs.TrySetResult(true)))
                {
                    if (connectTask != await Task.WhenAny(connectTask, tcs.Task).ConfigureAwait(false))
                    {
                        return false;
                    }

                    if (connectTask.Exception?.InnerException != null)
                    {
                        throw connectTask.Exception.InnerException;
                    }
                }
            }

            return true;
        }

        public void Free()
        {
            this.client.Dispose();
        }

        public void Dispose()
        {
            this.LastRelease = DateTimeOffset.UtcNow;
        }

        public NetworkStream GetStream()
        {
            return this.client.GetStream();
        }


    }


    internal static class CryptoPool
    {
        internal const int ClearAll = -1;

        internal static byte[] Rent(int minimumLength) => SharedRent<byte>(minimumLength);

        internal static T[] SharedRent<T>(int minimumLength)
        {
            var rentedBuffer = ArrayPool<T>.Shared.Rent(minimumLength);
            Array.Clear(rentedBuffer, 0, rentedBuffer.Length);

            return rentedBuffer;
        }


        internal static IMemoryOwner<T> Rent<T>(int minimumLength) => new CryptoMemoryOwner<T>(minimumLength);

        internal static IMemoryOwner<T> RentUnsafe<T>(int minimumLength) => new CryptoMemoryOwner<T>(minimumLength, false);

        internal static void Return<T>(T[] array, int clearSize = ClearAll)
        {
            bool clearWholeArray = clearSize < 0;

            if (!clearWholeArray && clearSize != 0)
            {
                Array.Clear(array, 0, clearSize);
            }

            ArrayPool<T>.Shared.Return(array, clearWholeArray);
        }
    }

    internal struct CryptoMemoryOwner<T> : IMemoryOwner<T>
    {
        private readonly T[] memory;
        private readonly bool clearAll;

        public CryptoMemoryOwner(int minimumLength, bool clearAll = true)
        {
            this.memory = CryptoPool.SharedRent<T>(minimumLength);
            this.clearAll = clearAll;

            this.Memory = new Memory<T>(this.memory);
        }

        public Memory<T> Memory { get; }

        public void Dispose()
        {
            CryptoPool.Return(this.memory, this.clearAll ? -1 : 0);
        }
    }
}
