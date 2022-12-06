using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using System.Threading.Tasks;

namespace criptografia
{
    internal class Program
    {
        static void Main(string[] args)
        {
            TestCryptoSimeticra();
        }

        static void TestAsimetrico(string strData)
        {
            rsa.EncryptRSA(strData);
            md5.Encrypt(strData);
            sha.ComputeSHA512(strData);
        }

        static void TestCryptoSimeticra()
        {
            string strKey = "MyTest";

            Console.WriteLine("Ingrese un texto a encryptar AES");
            string data = Console.ReadLine();
            AES.EncryptAesManaged(data);



            string dataDES = DES.EncryptData(data, strKey);

            Console.WriteLine("");
            Console.WriteLine($"Encrypted data (DES): {dataDES}");
            Console.WriteLine($"Dencrypted data (DES): {DES.DecryptData(dataDES, strKey)}");

            Console.WriteLine("Presion una tecla para generar RC4");
            Console.WriteLine("");
            Console.ReadKey();

            RC4Cryptography.Generate(data, "secret");

            Console.WriteLine("Presione una tecla para generar algoritmos de criptografía asimétrica");
            Console.WriteLine();
            Console.ReadKey();

            TestAsimetrico(data);

        }



    }
}
