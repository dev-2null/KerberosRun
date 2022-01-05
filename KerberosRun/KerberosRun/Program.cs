using System;
using CommandLine;

namespace KerberosRun
{
    public class Program
    {

        public static async System.Threading.Tasks.Task Main(string[] args)
        {

            PrintFunc.PrintBanner();
            var parser = new Parser(with =>
            {
                with.CaseInsensitiveEnumValues = true;
                with.CaseSensitive = false;
                with.HelpWriter = null;
            });

            parser.ParseArguments<Options>(args).WithParsed(o => { Options.Instance = o; }).WithNotParsed(error => { });
            parser.Dispose();

            var options = Options.Instance;
            if (options == null) { Options.GetHelp(); return; }

            if (options.Ticket == null & options.Asreproast == false & options.Kerberoast == false 
                & options.AskTGS == false & options.AskTGT == false & options.S4U == false
                & options.S4U2Self == false & options.Golden == false & options.Sliver == false)
            {
                Options.GetHelp();
                Environment.Exit(0);
            }

            await Commands.ResolveCmd(options);

            Console.WriteLine();
            
        }



    }

}


