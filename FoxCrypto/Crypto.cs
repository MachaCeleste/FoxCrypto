using System.Text;
using System.Security.Cryptography;

namespace FoxCrypto
{
    public class Crypto
    {
        #region PublicMethods
        /// <summary>
        /// Run AES256 crypt on given data using the passkey in the direction provided
        /// </summary>
        /// <param name="data">Data to be crypted</param>
        /// <param name="passkey">Passkey for locking crypt</param>
        /// <param name="direction">Default is encrypt, dec for decrypt</param>
        /// <returns>Encrypted or decrypted data</returns>
        public static string? Run(string data, string passkey, string direction = "enc")
        {
            byte[] salt = new byte[16];
            if (direction == "dec")
            {
                byte[] raw = Convert.FromBase64String(data);
                int index = Math.Min(raw.Length, salt.Length);
                Array.Copy(raw, salt, index);
                byte[] outdata = new byte[raw.Length - salt.Length];
                Array.Copy(raw, index, outdata, 0, outdata.Length);
                return Crypt(outdata, passkey, salt, direction);
            }
            else
            {
                RandomNumberGenerator.Fill(salt);
                byte[] clearBytes = Encoding.UTF8.GetBytes(data);
                return Crypt(clearBytes, passkey, salt);
            }
        }
        /// <summary>
        /// Run password through SHA256 before use in crypt
        /// </summary>
        /// <param name="password">Password</param>
        /// <returns>An SHA265 hashed version of the given password</returns>
        public static string GetPasskey(string password)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] iBytes = Encoding.UTF8.GetBytes(password);
                byte[] hash = sha.ComputeHash(iBytes);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("X2"));
                return sb.ToString();
            }
        }
        #endregion
        #region PrivateMethods
        private static string? Crypt(byte[] data, string passkey, byte[] salt, string direction = "enc")
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using (var key = new Rfc2898DeriveBytes(passkey, salt, 10000))
                {
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.IV = key.GetBytes(aes.BlockSize / 8);
                }
                ICryptoTransform cryptor;
                if (direction == "dec")
                    cryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                else
                    cryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (cryptor)
                {
                    if (direction == "dec")
                    {
                        byte[]? decBytes = DoCrypto(data, cryptor);
                        if (decBytes == null) return null;
                        return Encoding.UTF8.GetString(decBytes);
                    }
                    else
                    {
                        byte[]? encBytes = DoCrypto(data, cryptor);
                        if (encBytes == null) return null;
                        byte[] dataOut = new byte[salt.Length + encBytes.Length];
                        Array.Copy(salt, 0, dataOut, 0, salt.Length);
                        Array.Copy(encBytes, 0, dataOut, salt.Length, encBytes.Length);
                        return Convert.ToBase64String(dataOut);
                    }
                }
            }
        }
        private static byte[]? DoCrypto(byte[] data, ICryptoTransform transform)
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    try
                    {
                        cryptoStream.FlushFinalBlock();
                    }
                    catch
                    {
                        return null;
                    }
                    return memoryStream.ToArray();
                }
            }
        }
        #endregion
    }
}