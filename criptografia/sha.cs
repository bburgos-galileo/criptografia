using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace criptografia
{
    public class sha
    {
        static public void ComputeSHA512(string source)
        {
            StringBuilder sb = new StringBuilder();
            using (SHA512 sha512 = SHA512.Create())
            {
                byte[] hashValue = sha512.ComputeHash(Encoding.UTF8.GetBytes(source));
                foreach (byte b in hashValue)
                {
                    sb.Append($"{b:X2}");
                }
            }

            Console.WriteLine("El SHA-512 hash de " + source + " es: " + sb.ToString());
            Console.WriteLine("Presione una tecla para continuar");
            Console.ReadKey();
        }
    }
}
