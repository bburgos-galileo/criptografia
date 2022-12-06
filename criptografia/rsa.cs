using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace criptografia
{
    public static class rsa
    {
        static public byte[] Encryption(byte[] Data, RSAParameters RSAKey, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    RSA.ImportParameters(RSAKey);
                    encryptedData = RSA.Encrypt(Data, DoOAEPPadding);
                }
                return encryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }

        static public byte[] Decryption(byte[] Data, RSAParameters RSAKey, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    RSA.ImportParameters(RSAKey);
                    decryptedData = RSA.Decrypt(Data, DoOAEPPadding);
                }
                return decryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());
                return null;
            }
        }

        static public void EncryptRSA(string data)
        {
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            byte[] plaintext;
            byte[] encryptedtext;

            plaintext = ByteConverter.GetBytes(data);
            encryptedtext = Encryption(plaintext, RSA.ExportParameters(false), false);
            string encry = ByteConverter.GetString(encryptedtext);
            Console.WriteLine($"Encrypted data (RSA): {encry}");

            byte[] decryptedtex = Decryption(encryptedtext,RSA.ExportParameters(true), false);
            Console.WriteLine($"Decrypted data (RSA): {ByteConverter.GetString(decryptedtex)}");
            Console.WriteLine("Presione una tecla para continuar");
            Console.ReadKey();
            

        }
    }
}
