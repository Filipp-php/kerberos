using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Kerberos
{
    abstract class KerberosBaseSocket : KerberosSocket
    {
        protected IPHostEntry IpHost;
        protected IPAddress IpAddr;
        protected IPEndPoint LocalEndPoint;
        protected Aes AesEncryptor;

        public KerberosBaseSocket () {
            IpHost = Dns.GetHostEntry(Dns.GetHostName());
            IpAddr = IpHost.AddressList[0];
            LocalEndPoint = new IPEndPoint(IpAddr, 11111);
            AesEncryptor = Aes.Create();
        }

        public abstract void Start();

        public abstract void Close();

        protected long GetTimeStamp()
        {
            DateTime currentTime = DateTime.UtcNow;
            return ((DateTimeOffset)currentTime).ToUnixTimeSeconds();
        }

        protected byte[] GenerateSessionKey()
        {
            //Random random = new Random();
            //return random.Next().ToString();
            return Encoding.UTF8.GetBytes("mismaflkey123456");
        }

        protected long GeneratePeriod()
        {
            return 60; // minutes
        }

        protected byte[] CompleteAesBlock(byte[] block) {
            if (block.Length % 128 != 0 ) {
                byte [] newBlock = new byte[block.Length + (128 - block.Length % 128)];
                block.CopyTo(newBlock, 0);
                return newBlock;
            }
            return block;
        }

    }
}
