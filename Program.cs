using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Kerberos
{

    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 2)
            {
                if (args[0] == "server")
                {
                    string inputKey = args[1];
                    if (!File.Exists(inputKey))
                    {
                        Console.WriteLine("Файл для ввода данных не существует");
                        return;
                    }
                    byte[] buffer = File.ReadAllBytes(inputKey);
                    KerberosServer server = new KerberosServer(buffer, 123456789);
                    server.Start();
                    server.Close();
                }
            }
            if (args.Length == 3) { 
                if (args[0] == "kdc")
                {
                    string inputKey = args[1];
                    string inputServerDb = args[2];
                    if (!File.Exists(inputKey))
                    {
                        Console.WriteLine("Файл для ввода данных не существует");
                        return;
                    }
                    if (!File.Exists(inputKey))
                    {
                        Console.WriteLine("Файл для ввода клиентов не существует");
                        return;
                    }
                    byte[] bufferKey = File.ReadAllBytes(inputKey);
                    byte[] bufferClientDb = File.ReadAllBytes(inputServerDb);
                    string[] clientDbTmp = Encoding.UTF8.GetString(bufferClientDb).Split("\n");
                    string[][] clientDb = new string[clientDbTmp.Length][];
                    for (int i = 0; i < clientDbTmp.Length; i++)
                    {
                        clientDb[i] = clientDbTmp[i].Split(',');
                    }
                    KerberosAs kdc = new KerberosAs(bufferKey, clientDb);
                    kdc.Start();
                    kdc.Close();
                }
                if (args[0] == "tgs")
                {
                    string inputKey = args[1];
                    string inputServerDb = args[2];
                    if (!File.Exists(inputKey))
                    {
                        Console.WriteLine("Файл для ввода данных не существует");
                        return;
                    }
                    if (!File.Exists(inputKey))
                    {
                        Console.WriteLine("Файл для ввода серверов не существует");
                        return;
                    }
                    byte[] bufferKey = File.ReadAllBytes(inputKey);
                    byte[] bufferServerDb = File.ReadAllBytes(inputServerDb);
                    string[] serverDbTmp = Encoding.UTF8.GetString(bufferServerDb).Split("\n");
                    string[][] serverDb = new string[serverDbTmp.Length][];
                    for(int i = 0; i< serverDbTmp.Length; i++) {
                        serverDb[i] = serverDbTmp[i].Split(',');
                    }
                    KerberosTgs tgs = new KerberosTgs(bufferKey, serverDb, 123);
                    tgs.Start();
                    tgs.Close();
                }
                if (args[0] == "client")
                {
                    string inputKey = args[1];
                    string output = args[2];
                    if (!File.Exists(inputKey))
                    {
                        Console.WriteLine("Файл для ввода данных не существует");
                        return;
                    }
                    byte[] buffer = File.ReadAllBytes(inputKey);
                    KerberosClient client = new KerberosClient(123, 123, buffer, Encoding.UTF8.GetBytes("123456789"));
                    DateTime dateTime = DateTime.Now;
                    client.Start();
                    byte[] outputBuffer = 
                        Encoding.UTF8.GetBytes(
                            dateTime.ToString() + "\n" +
                            client.GetTimeFromServer().ToString()
                        );
                    client.Close();
                    File.WriteAllBytes(output, outputBuffer);
                }
            }
        }
    }
}