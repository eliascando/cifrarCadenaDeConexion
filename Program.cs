using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Org.BouncyCastle.Crypto.Digests;

namespace ConsoleApp1
{
    /// <summary>
    /// Programa privado usado para cifrar la cadena de conexión y contiene un método para descifrarla
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            string connectionString = "Data Source=elin.database.windows.net;Initial Catalog=SISTEMA_ERP;Persist Security Info=True;User ID=elin;Password=lagalletaasisequiebra1@";
            Console.WriteLine("Ingrese llave de encriptación");
            string entrada = Console.ReadLine();
            string encryptedKeyEncrypted = Encrypt(entrada);
            string encryptedConnectionString = EncryptConnectionString(connectionString,encryptedKeyEncrypted);
            Console.WriteLine("Llave de encriptación encriptada: " + encryptedKeyEncrypted);
            Console.WriteLine("Encrypted Connection String: " + encryptedConnectionString);
            string decryptedConnectionString = DecryptConnectionString(encryptedConnectionString, encryptedKeyEncrypted);
            Console.WriteLine("Decrypted Connection String: " + decryptedConnectionString);
        }

        public static string Encrypt(string entrada)
        {
            Sha3Digest sha3 = new Sha3Digest(256);
            byte[] inputBytes = Encoding.UTF8.GetBytes(entrada);
            byte[] hash = new byte[sha3.GetDigestSize()];
            sha3.BlockUpdate(inputBytes, 0, inputBytes.Length);
            sha3.DoFinal(hash, 0);
            return Convert.ToBase64String(hash);
        }

        static string EncryptConnectionString(string connectionString, string encryptionKey)
        {
            byte[] clearBytes = Encoding.Unicode.GetBytes(connectionString);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(encryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    connectionString = Convert.ToBase64String(ms.ToArray());
                }
            }
            return connectionString;
        }

        static string DecryptConnectionString(string connectionString, string encryptionKey)
        {
            connectionString = connectionString.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(connectionString);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(encryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    connectionString = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return connectionString;
        }
    }
}
