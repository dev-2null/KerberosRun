using System;
using System.DirectoryServices.ActiveDirectory;
using CommandLine;
using Kerberos.NET.Entities;

namespace KerberosRun
{
    public class Program
    {

        public static async System.Threading.Tasks.Task Main(string[] args)
        {
            Display.PrintBanner();
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

            Logging.LoadLoggingConfig();

            var KR = new KerberosRun(options);
            await KR.ResolveCommandAsync();

        }



    }

}


