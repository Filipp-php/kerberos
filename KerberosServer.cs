using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Kerberos
{
    class KerberosServer : KerberosBaseSocket
    {
        Socket Server;

        string KeyTgsSs = "nosmallkeu127322";

        long Id = 123456789;

        public KerberosServer() : base()
        {
            Server = new(IpAddr.AddressFamily,
                            SocketType.Stream,
                            ProtocolType.Tcp);
            LocalEndPoint = new IPEndPoint(IpAddr, 11115);
        }

        public byte[] PrepareResponseToClient(byte[] response)
        {
            byte[] tgsEncrypted = new byte[response[0]];
            int i = 2;
            for (; i < tgsEncrypted.Length + 2; i++)
            {
                tgsEncrypted[i - 2] = response[i];
            }
            byte[] authEncrypted = new byte[response[1]];
            for (; i < authEncrypted.Length + tgsEncrypted.Length + 2; i++)
            {
                authEncrypted[i - tgsEncrypted.Length - 2] = response[i];
            }

            AesEncryptor.Key = Encoding.UTF8.GetBytes(KeyTgsSs);
            byte[] tgs = AesEncryptor.DecryptEcb(tgsEncrypted, PaddingMode.Zeros);
            var tgsArray = Encoding.UTF8.GetString(tgs).Split("<|S|>");
            byte[] keyClientSs = Encoding.UTF8.GetBytes(tgsArray[tgsArray.Length - 1], 0, 16);
            AesEncryptor.Key = keyClientSs;
            byte[] auth = AesEncryptor.DecryptEcb(authEncrypted, PaddingMode.Zeros);
            var authArray = Encoding.UTF8.GetString(auth).Split("<|S|>");

            var clientFromTgs = long.Parse(tgsArray[0]);
            var ssId = long.Parse(tgsArray[1]);
            var timeStamp3 = long.Parse(tgsArray[2]);
            var period2 = long.Parse(tgsArray[3]);

            var client = long.Parse(authArray[0]);
            var timeStamp4 = long.Parse(authArray[1]);

            if (client == clientFromTgs && GetTimeStamp() < timeStamp4 + period2 * 3600
                && timeStamp4 == timeStamp3 && ssId == Id)
            {
                var message = Encoding.UTF8.GetBytes((timeStamp4 + 1).ToString());
                return AesEncryptor.EncryptEcb(message, PaddingMode.Zeros);
                
            }
            return new byte[0];
        }

        public override void Start()
        {
            Server.Bind(LocalEndPoint);
            Server.Listen(100);

            var handler = Server.Accept();
            while (true)
            {
                var buffer = new byte[1_024];
                var received = handler.Receive(buffer, SocketFlags.None);
                if (buffer.Length > 0)
                {
                    Console.WriteLine("Socket server recieved message from client...");
                    handler.Send(PrepareResponseToClient(buffer), 0);
                    Console.WriteLine("Socket server sent message to client...");
                    break;
                }
            }
        }


        public void Start1()
        {
            Server.Bind(LocalEndPoint);
            Server.Listen(100);

            var handler = Server.Accept();
            while (true)
            {
                // Receive message.
                var buffer = new byte[1_024];
                var received = handler.Receive(buffer, SocketFlags.None);
                var response = Encoding.UTF32.GetString(buffer, 0, received);

                var eom = "<|EOM|>";
                if (response.IndexOf(eom) > -1 /* is end of message */)
                {
                    Console.WriteLine(
                        $"Socket server received message: \"{response.Replace(eom, "")}\"");

                    var ackMessage = "<|ACK|>";
                    var echoBytes = Encoding.UTF32.GetBytes(ackMessage);
                    handler.Send(echoBytes, 0);
                    Console.WriteLine(
                        $"Socket server sent acknowledgment: \"{ackMessage}\"");

                    break;
                }
                // Sample output:
                //    Socket server received message: "Hi friends 👋!"
                //    Socket server sent acknowledgment: "<|ACK|>"
            }
        }

        public override void Close()
        {
            Server.Close();
        }
    }
}
