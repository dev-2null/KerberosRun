using System;
using CommandLine;

namespace KerberosRun
{
    class MainClass
    {

        public static async System.Threading.Tasks.Task Main(string[] args)
        {

            PrintFunc.PrintBanner();
            
            var options = new Options();
            if (!Parser.Default.ParseArguments(args, options)) { return; }
            if (options.Ticket == null & options.Asreproast == false & options.Kerberoast == false 
                & options.AskTGS == false & options.AskTGT == false & options.S4U == false
                & options.S4U2Self == false & options.Golden == false & options.Sliver == false)
            {
                Console.WriteLine(options.GetHelp());
                Environment.Exit(0);
            }

            await Commands.ResolveCmd(options);

            Console.WriteLine();
            
        }



    }

}


