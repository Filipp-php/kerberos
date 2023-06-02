using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Security.Cryptography;

namespace Kerberos
{
    class KerberosClient : KerberosBaseSocket
    {

        Socket Client;
        long Id;
        long Tgs;
        string KeyClient;
        byte[] KeyClientTgs;
        byte[] KeyClientSs;

        public KerberosClient(long id, long tgs) : base()
        {
            CreateClient();
            Id = id;
            Tgs = tgs;
            KeyClient = "mysmallkey127426";
            KeyClientTgs = new byte[16];
            KeyClientTgs = new byte[16];
        }

        private void CreateClient() {
            Client = new(IpAddr.AddressFamily,
                            SocketType.Stream,
                            ProtocolType.Tcp);
        }

        private byte[] PrepareMessageToAs () {
            byte[] msg = Encoding.UTF8.GetBytes(Id.ToString() +
                                                "<|S|>" + 
                                                Tgs.ToString());
            return msg;
        }

        private byte[] PrepareMessageToTgs(byte[] responseFromAs)
        {
            byte[] server = Encoding.UTF8.GetBytes("123456789");
            byte[] tgtEncrypted = new byte[responseFromAs.Length - 16];
            KeyClientTgs = new byte[16];
            int i = 0;
            for (; i < 16; i++) {
                KeyClientTgs[i] = responseFromAs[i];
            }
            for (; i < responseFromAs.Length; i++){
                tgtEncrypted[i-16] = responseFromAs[i];
            }
            long timeStamp = GetTimeStamp();
            byte[] auth = Encoding.UTF8.GetBytes(Id.ToString() + "<|S|>" + timeStamp.ToString());
            AesEncryptor.Key = KeyClientTgs;
            byte[] authEncrypted = AesEncryptor.EncryptEcb(auth, PaddingMode.Zeros);
            byte[] message = new byte[tgtEncrypted.Length + authEncrypted.Length + server.Length + 3];
            message[0] = (byte)tgtEncrypted.Length;
            message[1] = (byte)authEncrypted.Length;
            message[2] = (byte)server.Length;
            tgtEncrypted.CopyTo(message, 3);
            authEncrypted.CopyTo(message, tgtEncrypted.Length+3);
            server.CopyTo(message, tgtEncrypted.Length + authEncrypted.Length + 3);
            return message;
        }

        private byte[] PrepareMessageToSs(byte[] responseFromTgs)
        {
            byte[] tgsEncrypted = new byte[responseFromTgs.Length - 16];
            KeyClientSs = new byte[16];
            int i = 0;
            for (; i < 16; i++)
            {
                KeyClientSs[i] = responseFromTgs[i];
            }
            for (; i < responseFromTgs.Length; i++)
            {
                tgsEncrypted[i - 16] = responseFromTgs[i];
            }
            long timeStamp = GetTimeStamp();
            byte[] auth = Encoding.UTF8.GetBytes(Id.ToString() + "<|S|>" + timeStamp.ToString());
            AesEncryptor.Key = KeyClientSs;
            byte[] authEncrypted = AesEncryptor.EncryptEcb(auth, PaddingMode.Zeros);
            byte[] message = new byte[tgsEncrypted.Length + authEncrypted.Length + 2];
            message[0] = (byte)tgsEncrypted.Length;
            message[1] = (byte)authEncrypted.Length;
            tgsEncrypted.CopyTo(message, 2);
            authEncrypted.CopyTo(message, tgsEncrypted.Length + 2);
            return message;
        }

        private byte[] SendMessToAs() {
            Client.Connect(LocalEndPoint);
            while (true)
            {
                _ = Client.Send(PrepareMessageToAs(), SocketFlags.None);
                Console.WriteLine("Socket client sent message to auth server...");
                var buffer = new byte[1_024];
                int received = Client.Receive(buffer, SocketFlags.None);
                if (buffer.Length > 0) {
                    Console.WriteLine("Socket client recieved message from auth server...");
                    AesEncryptor.Key = Encoding.UTF8.GetBytes(KeyClient);
                    byte[] result = AesEncryptor.DecryptEcb(buffer, PaddingMode.Zeros);
                    Client.Shutdown(SocketShutdown.Both);
                    Client.Disconnect(true);
                    byte[] response = new byte[received];
                    for (int i = 0; i < received; i++) {
                        response[i] = result[i];
                    }
                    return response;
                }
            }
        }

        private byte[] SendMessToTgs(byte[] responseFromAs)
        {
            CreateClient();
            Client.Connect(new IPEndPoint(IpAddr, 11113));
            while (true)
            {
                _ = Client.Send(PrepareMessageToTgs(responseFromAs), SocketFlags.None);
                Console.WriteLine("Socket client sent message to tgs...");
                var buffer = new byte[1_024];
                var received = Client.Receive(buffer, SocketFlags.None);
                if (buffer.Length > 0)
                {
                    Console.WriteLine("Socket client recieved message from tgs...");
                    AesEncryptor.Key = KeyClientTgs;
                    byte[] result = AesEncryptor.DecryptEcb(buffer, PaddingMode.Zeros);
                    Client.Shutdown(SocketShutdown.Both);
                    Client.Disconnect(true);
                    byte[] response = new byte[received];
                    for (int i = 0; i < received; i++)
                    {
                        response[i] = result[i];
                    }
                    return response;
                }
            }
        }

        private byte[] SendMessToSs(byte[] responseFromTgs)
        {
            CreateClient();
            Client.Connect(new IPEndPoint(IpAddr, 11115));
            while (true)
            {
                _ = Client.Send(PrepareMessageToSs(responseFromTgs), SocketFlags.None);
                Console.WriteLine("Socket client sent message to server...");
                var buffer = new byte[1_024];
                var received = Client.Receive(buffer, SocketFlags.None);
                if (buffer.Length > 0)
                {
                    Console.WriteLine("Socket client recieved message from server...");
                    AesEncryptor.Key = KeyClientTgs;
                    byte[] result = AesEncryptor.DecryptEcb(buffer, PaddingMode.Zeros);
                    Client.Shutdown(SocketShutdown.Both);
                    Client.Disconnect(true);
                    byte[] response = new byte[received];
                    for (int i = 0; i < received; i++)
                    {
                        response[i] = result[i];
                    }
                    return response;
                }
            }
        }

        public override void Start()
        {
            DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            Console.WriteLine(dateTime.AddSeconds(GetTimeStamp()).ToLocalTime());
            var responseFromAs = SendMessToAs();
            var responseFromTgs = SendMessToTgs(responseFromAs);
            var responseFromServer = SendMessToSs(responseFromTgs);
            dateTime = dateTime.AddSeconds(double.Parse(Encoding.UTF8.GetString(responseFromServer))).ToLocalTime();
            Console.WriteLine(dateTime);
        }

        public void Start1()
        {
            Client.Connect(LocalEndPoint);
            while (true)
            {
                // Send message.
                var message = "Hi friends 👋!<|EOM|>";
                var messageBytes = Encoding.UTF8.GetBytes(message);
                _ = Client.Send(messageBytes, SocketFlags.None);
                Console.WriteLine($"Socket client sent message: \"{message}\"");

                // Receive ack.
                var buffer = new byte[1_024];
                var received = Client.Receive(buffer, SocketFlags.None);
                var response = Encoding.UTF8.GetString(buffer, 0, received);
                if (response == "<|ACK|>")
                {
                    Console.WriteLine(
                        $"Socket client received acknowledgment: \"{response}\"");
                    break;
                }
                // Sample output:
                //     Socket client sent message: "Hi friends 👋!<|EOM|>"
                //     Socket client received acknowledgment: "<|ACK|>"
            }
        }

        public override void Close()
        {
            Client.Close();
        }
    }
}
