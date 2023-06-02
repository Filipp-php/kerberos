using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using static System.Net.Mime.MediaTypeNames;

namespace Kerberos
{
    class KerberosTgs : KerberosBaseSocket
    {
        Socket Server;

        string KeyTgs = "mysmallkey123456";

        long Id = 123;

        string[][] ServerDb;

        public KerberosTgs() : base()
        {
            Server = new(IpAddr.AddressFamily,
                            SocketType.Stream,
                            ProtocolType.Tcp);
            LocalEndPoint = new IPEndPoint(IpAddr, 11113);
            ServerDb = new string[][] {
                        new string [] {"123456789", "nosmallkeu127322" },
                        }; // id, key_tgs_ss

        }

        public byte[] PrepareResponseToClient(byte[] response)
        {
            byte[] tgtEncrypted = new byte[response[0]];
            int i = 3;
            for (; i < tgtEncrypted.Length+3; i++){
                tgtEncrypted[i-3] = response[i];
            }
            byte[] authEncrypted = new byte[response[1]];
            for (; i < authEncrypted.Length + tgtEncrypted.Length+3; i++)
            {
                authEncrypted[i - tgtEncrypted.Length - 3] = response[i];
            }
            byte[] serverArr = new byte[response[2]];
            for (; i < serverArr.Length + authEncrypted.Length + tgtEncrypted.Length+3; i++)
            {
                serverArr[i - authEncrypted.Length - tgtEncrypted.Length - 3] = response[i];
            }

            AesEncryptor.Key = Encoding.UTF8.GetBytes(KeyTgs);
            byte[] tgt = AesEncryptor.DecryptEcb(tgtEncrypted, PaddingMode.Zeros);
            var tgtArray = Encoding.UTF8.GetString(tgt).Split("<|S|>");
            byte[] keyClientTgs = Encoding.UTF8.GetBytes(tgtArray[tgtArray.Length-1], 0, 16);
            AesEncryptor.Key = keyClientTgs;
            byte[] auth = AesEncryptor.DecryptEcb(authEncrypted, PaddingMode.Zeros);
            var authArray = Encoding.UTF8.GetString(auth).Split("<|S|>");

            var clientFromServer = long.Parse(tgtArray[0]);
            var tgsId = long.Parse(tgtArray[1]);
            var timeStamp1 = long.Parse(tgtArray[2]);
            var period = long.Parse(tgtArray[3]);

            var client = long.Parse(authArray[0]);
            var timeStamp2 = long.Parse(authArray[1]);
            var server = Encoding.UTF8.GetString(serverArr);

            if (client == clientFromServer && GetTimeStamp() < timeStamp2 + period * 3600
                && timeStamp2 == timeStamp1 && tgsId == Id)
            {
                string keyTgsSs = "";
                for (i = 0; i < ServerDb.Length; i++)
                {
                    if (ServerDb[i][0] == server)
                    {
                        keyTgsSs = ServerDb[i][1];
                    }
                }
                if (keyTgsSs != "")
                {
                    long timeStamp = GetTimeStamp();
                    long period2 = GeneratePeriod();
                    byte[] keyClientServer = GenerateSessionKey();
                    var tgs = Encoding.UTF8.GetBytes(client.ToString() + "<|S|>" +
                              server.ToString() + "<|S|>" +
                              timeStamp.ToString() + "<|S|>" +
                              period2.ToString() + "<|S|>" +
                              Encoding.UTF8.GetString(keyClientServer));
                    AesEncryptor.Key = Encoding.UTF8.GetBytes(keyTgsSs);
                    byte[] tgsEncrypted = AesEncryptor.EncryptEcb(tgs, PaddingMode.Zeros);
                    byte[] message = new byte[keyClientServer.Length + tgsEncrypted.Length];
                    keyClientServer.CopyTo(message, 0);
                    tgsEncrypted.CopyTo(message, keyClientServer.Length);
                    AesEncryptor.Key = keyClientTgs;
                    return AesEncryptor.EncryptEcb(message, PaddingMode.Zeros);
                }
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
                    Console.WriteLine("Socket tgs recieved message from client...");
                    handler.Send(PrepareResponseToClient(buffer), 0);
                    Console.WriteLine("Socket tgs sent message to client...");
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
