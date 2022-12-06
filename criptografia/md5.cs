using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace criptografia
{
    public static class md5
    {
        public static void Encrypt(string strdata)
        {
            GetMd5Hash(strdata);
        }

        static void GetMd5Hash(string input)
        {
            var source = input;

            // Creates an instance of the default implementation of the MD5 hash algorithm.
            using (var md5Hash = MD5.Create())
            {
                // Byte array representation of source string
                var sourceBytes = Encoding.UTF8.GetBytes(input);

                // Generate hash value(Byte Array) for input data
                var hashBytes = md5Hash.ComputeHash(sourceBytes);

                // Convert hash byte array to string
                var hash = BitConverter.ToString(hashBytes).Replace("-", string.Empty);

                // Output the MD5 hash
                Console.WriteLine("El MD5 hash de " + source + " es: " + hash);
                Console.WriteLine("Presione una tecla para continuar");
                Console.ReadKey();
            }
        }



    }
}
