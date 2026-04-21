using System.Security.Cryptography;
using System.Text;

namespace Shared.Engine
{
    public static class UnicTo
    {
        static string ArrayList => "qwertyuioplkjhgfdsazxcvbnmQWERTYUIOPLKJHGFDSAZXCVBNM1234567890";
        static string ArrayListToNumber => "1234567890";

        // Why: these codes are handed out as merchant invoice ids, one-shot
        // auth tokens, and sample creds in admin HTML. Random.Shared is a
        // non-cryptographic PRNG — predictable from one sample to the next.
        // Use the OS CSPRNG so values cannot be enumerated.
        public static string Code(int size = 8, bool IsNumberCode = false)
        {
            StringBuilder array = new StringBuilder();
            for (int i = 0; i < size; i++)
            {
                array.Append(ArrayList[RandomNumberGenerator.GetInt32(0, 61)]);
            }

            return array.ToString();
        }

        public static string Number(int size = 8)
        {
            StringBuilder array = new StringBuilder();
            for (int i = 0; i < size; i++)
            {
                array.Append(ArrayListToNumber[RandomNumberGenerator.GetInt32(0, 9)]);
            }

            return array.ToString();
        }
    }
}
