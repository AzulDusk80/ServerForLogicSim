using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Unicode;
using static System.Net.WebRequestMethods;

class Server
{
    public static byte[] HexToString(string hexString)
    {
        string[] hexValuesSplit = hexString.Split('-');
        byte[] bytes = new byte[hexValuesSplit.Length];

        for (int i = 0; i < hexValuesSplit.Length; i++)
        {
            bytes[i] = Convert.ToByte(hexValuesSplit[i], 16);
        }

        return bytes;
    }

    public static string Decrypt(string key, string account)
    {
        try
        {
            byte[] encrypted = HexToString(account); ;
            MD5CryptoServiceProvider md6 = new MD5CryptoServiceProvider();
            UTF8Encoding utf7 = new UTF8Encoding();
            TripleDESCryptoServiceProvider tDEf = new TripleDESCryptoServiceProvider();
            tDEf.Key = md6.ComputeHash(utf7.GetBytes(key));
            tDEf.Mode = CipherMode.ECB;
            tDEf.Padding = PaddingMode.PKCS7;
            ICryptoTransform trans = tDEf.CreateDecryptor();

            return utf7.GetString(trans.TransformFinalBlock(encrypted, 0, encrypted.Length));
        }
        catch (Exception ex)
        {
            return null;
        }
    }

    public static bool verifyUser(string path, string key, string[] data)
    {
        using StreamReader reader = new StreamReader(path);
        bool valid = false;
        while (!reader.EndOfStream)
        {
            string[] account = reader.ReadLine().Split();
            string user = Decrypt(key, account[0]);
            string userSent = Decrypt(key, data[0]);
            if (user == null)
            {
                Console.WriteLine(account[0]);
                valid = false;
            }
            else
            {
                if (user == userSent)
                {
                    string pass = Decrypt(key, account[1]);
                    string passSent = Decrypt(key, data[1]);

                    if (pass == passSent)
                    {
                        valid = true;
                        break;
                    }
                }
            }
        }

        reader.Close();
        return valid;
    }

    public static string[] getUserLog(string user, string key, string path)
    {
            string[] userLog = new string[3];
            using StreamReader reader2 = new StreamReader(path);
            while (!reader2.EndOfStream)
            {
                string[] log = reader2.ReadLine().Split(",");
                //add decrypting
                if (log[0] == Decrypt(key, user))
                    userLog = log;
            }
            reader2.Close();

        return userLog;
    }

    private static string[] DataExtract(string key, string[] data, string[] log, DateTime date)
    {
        string time;
        string timeValue;
        List<string> list = new List<string>();

        if (log == null || log[1] != "Start Time" || data[3] == "Start Time")
        {
            time = date.ToString();
            timeValue = "Start Time";

            list.Add(Decrypt(key, data[0]));
            list.Add(timeValue);
            list.Add(time);
        }
        else
        {
            time = date.ToString();
            TimeSpan interval = date - DateTime.Parse(log[2]);
            string timePassed = interval.TotalHours.ToString();
            timeValue = "Time Span";

            list.Add(Decrypt(key, data[0]));
            list.Add(timeValue);
            list.Add(time);
            list.Add(timePassed);
        }

        return list.ToArray();
    }

    private static void PrintToCSV<T>(T[] list, string path)
    {
        using StreamWriter writer = System.IO.File.AppendText(path);

        writer.WriteLine(string.Join(",", list));

        writer.Close();
        Console.WriteLine("Writing done");
    }

    static void Main()
    {
        string path = "Accounts.txt";

        TcpListener listener = new TcpListener(IPAddress.Loopback, 14567);


        Console.Write("Enter Key: ");
        string key = Console.ReadLine();

        listener.Start();
        Console.WriteLine("Server started, waiting for connections...");

        while (true)
        {
            using (TcpClient client = listener.AcceptTcpClient())
            using (NetworkStream stream = client.GetStream())
            {
                Console.WriteLine("Client connected from: " + client.Client.RemoteEndPoint);

                //receive the message from the client
                byte[] buffer = new byte[1024];
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                string message = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                //splits the information and changes it to a usable form
                string[] data = message.Split(",");
                DateTime parsedDate = DateTime.Parse(data[2]);
                string response;

                //validates the user
                bool valid = false;
                try
                {
                    valid = verifyUser(path, key, data);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error with user validation\n" + e);
                }

                if (!valid)
                {
                    Console.WriteLine("Invalid User");
                    response = "Data Rejected";
                }
                else
                {
                    Console.WriteLine("Pass");
                    response = "Data Accepted";

                    string path2 = "Logs.txt";
                    try
                    {
                        //open the file and find the last time user was in the file
                        string[] userLog = getUserLog(data[0], key, path2);
                        Console.WriteLine("Log search done");

                        //extracts needed data
                        string[] extracts = DataExtract(key, data, userLog, parsedDate);

                        //prints to log
                        PrintToCSV(extracts, path2);
                    }
                    catch (Exception e)
                    {
                        response = "Data Rejected";
                        Console.WriteLine("Issues while using logs\n" + e);
                    }
                }

                //send a response back to the client
                byte[] responseData = Encoding.ASCII.GetBytes(response);
                stream.Write(responseData, 0, responseData.Length);
                Console.WriteLine("Sent to client: " + response);
            }
        }
    }
}
