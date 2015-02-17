using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using BrockAllen.MembershipReboot;

namespace MembershipReboot.Contrib
{
    public class BCrypto : ICrypto
    {
        private readonly int _workFactor;

        public BCrypto(int workFactor)
        {
            _workFactor = workFactor;
        }

        public string Hash(string value)
        {
            return BCrypt.Net.BCrypt.HashPassword(value, _workFactor);
        }

        public bool VerifyHash(string value, string hash)
        {
            return BCrypt.Net.BCrypt.Verify(value, hash);
        }

        public string Hash(string value, string key)
        {
            return BCrypt.Net.BCrypt.HashPassword(value, _workFactor);
        }

        public bool VerifyHash(string value, string key, string hash)
        {
            return this.VerifyHashedPassword(hash, value);
        }

        public string GenerateNumericCode(int digits)
        {
            // 18 is good size for a long
            if (digits > 18) digits = 18;
            if (digits <= 0) digits = 6;
            string str = BCrypt.Net.BCrypt.GenerateSalt(sizeof(long)); ;
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);

            var val = BitConverter.ToInt64(bytes, 0);
            var mod = (int)Math.Pow(10, digits);
            val %= mod;
            val = Math.Abs(val);

            return val.ToString("D" + digits);
        }

        public string GenerateSalt()
        {
            return BCrypt.Net.BCrypt.GenerateSalt();
        }

        public string HashPassword(string password, int iterations)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, iterations);
        }

        public bool VerifyHashedPassword(string hashedPassword, string password)
        {
            bool result;
            try
            {
                result = BCrypt.Net.BCrypt.Verify(password, hashedPassword);
            }
            catch (Exception ep)
            {
                try
                {
                    // the hash could be generated from older BCrypt version
                    result = BCrypt.Net.BCrypt.Verify(password, ReplaceFirst(hashedPassword, "2a", "2y"));
                }
                catch (Exception ep2)
                {
                    // the hash could be generated from other hash library
                    result = false;
                }

            }

            return result;
        }

        string ReplaceFirst(string text, string search, string replace)
        {
            int pos = text.IndexOf(search);
            if (pos < 0)
            {
                return text;
            }
            return text.Substring(0, pos) + replace + text.Substring(pos + search.Length);
        }
    }
}
