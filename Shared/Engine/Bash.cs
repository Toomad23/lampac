using System.Diagnostics;

namespace Shared.Engine
{
    public static class Bash
    {
        // HIGH-6: build the ProcessStartInfo via ArgumentList rather than concatenating the
        // caller-supplied string into a shell-quoted `-c "…"`. The old escaping only handled
        // '"' and '\''; backticks, $( ), ;, &, | all survived, so any caller that ever passed
        // attacker-influenced text (current call-sites are admin/config-only, but fragile)
        // could achieve shell metacharacter injection. ArgumentList hands each slot to the
        // kernel's argv directly; bash still interprets the SINGLE `-c` payload but there is
        // no longer a concatenation boundary where a caller string can break out of its slot.
        static ProcessStartInfo MakeInfo(string command, bool redirectStderr)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "/bin/bash",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = redirectStderr,
            };
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add(command ?? string.Empty);
            return psi;
        }

        public static bool Invoke(string comand)
        {
            try
            {
                var process = Process.Start(MakeInfo(comand, redirectStderr: false));
                if (process == null)
                    return false;

                return true;
            }
            catch
            {
                return false;
            }
        }

        async public static Task<string> Run(string comand)
        {
            try
            {
                var process = Process.Start(MakeInfo(comand, redirectStderr: true));
                if (process == null)
                    return null;

                string outPut = await process.StandardOutput.ReadToEndAsync();
                outPut += await process.StandardError.ReadToEndAsync();

                await process.WaitForExitAsync();

                return outPut;
            }
            catch
            {
                return null;
            }
        }
    }
}
