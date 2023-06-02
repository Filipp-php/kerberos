using System.Net.Sockets;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Text;

namespace Kerberos
{
    class KerberosAs : KerberosBaseSocket
    {
        Socket Server;

        string[][] ClientDb;

        string KeyTgs = "mysmallkey123456";

        public KerberosAs()
        {
            Server = new(IpAddr.AddressFamily,
                            SocketType.Stream,
                            ProtocolType.Tcp);
            ClientDb = new string[][] { 
                        new string [] {"123", "mysmallkey127426" }, 
                        }; // id, password (key_c)
        }

        public byte[] PrepareResponseToClient(string response) {
            var responseArray = response.Split("<|S|>");
            string client = responseArray[0];
            string tgs = responseArray[1];
            string keyClient = "";
            for (int i = 0; i < ClientDb.Length; i++) {
                if (ClientDb[i][0] == client) {
                    keyClient = ClientDb[i][1];
                }
            }
            if (keyClient != "") {
                long timeStamp = GetTimeStamp();
                long period = GeneratePeriod();
                byte[] keyClientTgs = GenerateSessionKey();
                var tgt = Encoding.UTF8.GetBytes(client.ToString() + "<|S|>" + 
                          tgs.ToString() + "<|S|>" +
                          timeStamp.ToString() + "<|S|>" +
                          period.ToString() + "<|S|>" +
                          Encoding.UTF8.GetString(keyClientTgs));
                AesEncryptor.Key = Encoding.UTF8.GetBytes(KeyTgs);
                byte[] tgtEncrypted = AesEncryptor.EncryptEcb(tgt, PaddingMode.Zeros);
                byte[] message = new byte[keyClientTgs.Length + tgtEncrypted.Length];
                keyClientTgs.CopyTo(message, 0);
                tgtEncrypted.CopyTo(message, keyClientTgs.Length);
                AesEncryptor.Key = Encoding.UTF8.GetBytes(keyClient);
                return AesEncryptor.EncryptEcb(message, PaddingMode.Zeros);
            }
            return new byte[0];
        }

        public override void Start() {
            Server.Bind(LocalEndPoint);
            Server.Listen(100);

            var handler = Server.Accept();
            while (true)
            {
                var buffer = new byte[1_024];
                var received = handler.Receive(buffer, SocketFlags.None);
                var response = Encoding.UTF8.GetString(buffer, 0, received);
                if (buffer.Length > 0)
                {
                    Console.WriteLine("Socket server recieved message from client...");
                    handler.Send(PrepareResponseToClient(response), 0);
                    Console.WriteLine("Socket server sent message to client...");
                    break;
                }
            }
        }

        public override void Close()
        {
            Server.Close();
        }
    }
}
