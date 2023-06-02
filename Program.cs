using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Kerberos
{

    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 1) {
                if (args[0] == "server") {
                    KerberosServer server = new KerberosServer();
                    server.Start();
                    server.Close();
                }
                if (args[0] == "kdc")
                {
                    KerberosAs kdc = new KerberosAs();
                    kdc.Start();
                    kdc.Close();
                }
                if (args[0] == "tgs")
                {
                    KerberosTgs tgs = new KerberosTgs();
                    tgs.Start();
                    tgs.Close();
                }
                if (args[0] == "client")
                {
                    KerberosClient client = new KerberosClient(123, 123);
                    client.Start();
                    client.Close();
                }
            }
        }
    }
}