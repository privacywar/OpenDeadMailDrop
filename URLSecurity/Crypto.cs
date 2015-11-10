// LICENSE
// You are hereafter granted an unending, unlimited, license to make use of,
// derivative works of, and free distributions of, the source code and contents
// of this file.
//
// DISCLAIMER
// BECAUSE THIS FILE IS LICENSED FREE OF CHARGE, THERE IS NO
// WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE
// LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
// HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT
// WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT
// NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS TO THE
// QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
// PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY
// SERVICING, REPAIR OR CORRECTION.
//
// IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN
// WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY
// MODIFY AND/OR REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE
// LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL,
// INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR
// INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF
// DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU
// OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY
// OTHER PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
//
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Security;
using System.IO.Compression;

namespace OpenDMD.URLSecurity
{
    /// <summary>
    /// Provides cryptographic services
    /// </summary>
    public sealed class Crypto
    {
        private readonly static byte[] _PadKey = new byte[] { 0x69, 0xfe, 0xee, 0x70, 0xbe, 0xef, 0x96 };
        private static string _COMMON_KEY = "[enter something here]";
        private static char _MARKER = '_';
        private static char _Base64MARKER = '-';

        #region MD5
        /// <summary>
		/// Returns an MD5 hashed and base64-encoded result from the given plain text.
		/// </summary>
		/// <param name="plainText"></param>
		/// <returns></returns>
		public static string HashBase64(string plainText)
		{
			MD5 sp = MD5CryptoServiceProvider.Create();
			byte[] hash = sp.ComputeHash(System.Text.Encoding.Default.GetBytes(plainText));
			return(Convert.ToBase64String(hash));
		}

        /// <summary>
        /// Returns an MD5 hashed and hex-encoded result from the given plain text.
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        public static string Hash(string plainText)
        {
            MD5 sp = MD5CryptoServiceProvider.Create();
            byte[] hash = sp.ComputeHash(System.Text.Encoding.Default.GetBytes(plainText));
            // Convert the hash to a hex-encoded string
            string ss = HexStringFromBytes(hash, hash.Length);
            return(ss);
        }
        #endregion

        #region SHA512
        /// <summary>
        /// Returns an SHA512 hashed and base64-encoded result from the given plain text.
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        public static string SHAHashBase64(string plainText)
        {
            SHA512 sp = SHA512CryptoServiceProvider.Create();
            byte[] hash = sp.ComputeHash(System.Text.Encoding.Default.GetBytes(plainText));
            return (Convert.ToBase64String(hash));
        }

        /// <summary>
        /// Returns an SHA512 hashed and hex-encoded result from the given plain text.
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        public static string SHAHash(string plainText)
        {
            SHA512 sp = SHA512CryptoServiceProvider.Create();
            byte[] hash = sp.ComputeHash(System.Text.Encoding.Default.GetBytes(plainText));
            // Convert the hash to a hex-encoded string
            string ss = HexStringFromBytes(hash, hash.Length);
            return (ss);
        }
        #endregion

        private static byte[] MakeCipherKey(string key, SymmetricAlgorithm algo)
        {
            byte[] bytesKey = System.Text.Encoding.Default.GetBytes(key);
            int nKeyBytes = algo.KeySize / 8;
            if(bytesKey.Length > nKeyBytes) 
            {
                byte[] bb = new byte[nKeyBytes];
                Array.Copy(bytesKey, 0L, bb, 0L, (long)nKeyBytes);
                bytesKey = bb;
            }
            else if(bytesKey.Length < nKeyBytes) 
            {
                byte[] bb = new byte[nKeyBytes];
                for(int i=0; i < nKeyBytes; i++) 
                {
                    if(i >= bytesKey.Length) 
                    {
                        bb[i] = _PadKey[(i - bytesKey.Length) % _PadKey.Length];
                    }
                    else 
                    {
                        bb[i] = bytesKey[i];
                    }
                }
                bytesKey = bb;
            }
            return(bytesKey);
        }

        #region DES Decryption
        /// <summary>
		/// Decrypts the given data using the common key.
		/// </summary>
		/// <param name="strData"></param>
		/// <returns></returns>
		public static string Decrypt(string strData)
		{
			return(Decrypt(strData, _COMMON_KEY));
		}

        /// <summary>
        /// Decrypts the given data using the common key.
        /// </summary>
        /// <param name="strData"></param>
        /// <returns>The original plain text as a byte array.</returns>
        public static byte[] DecryptToBytes(string strData)
        {
            return (DecryptToBytes(strData,_COMMON_KEY));
        }

        /// <summary>
        /// Decrypts the given data using the common key.
        /// </summary>
        /// <param name="strData"></param>
        /// <returns>The original plain text as a byte array.</returns>
        public static byte[] DecryptBase64ToBytes(string strData)
        {
            return (DecryptBase64ToBytes(strData,_COMMON_KEY));
        }

        /// <summary>
        /// Decrypts the given string of cipher text with the given key string.  The IV for the
        /// cipher text is assumed to be appended to the cipher text after a MARKER character, e.g.
        /// 123544151-43234324.  This method uses DES as the crypto provider and assumes also 
        /// that the cipher text is hexadecimal encodes.
        /// </summary>
        /// <param name="strData">The cipher text + the IV</param>
        /// <param name="strKey">The cipher key</param>
        /// <returns>The plain text</returns>
        public static string Decrypt(string strData, string strKey)
        {
            byte[] plain = DecryptToBytes(strData,strKey);
            string strText = System.Text.Encoding.Default.GetString(plain);
            return(strText);
        }

        /// <summary>
        /// Decrypts the given string of cipher text with the given key string.  The IV for the
        /// cipher text is assumed to be appended to the cipher text after a MARKER character, e.g.
        /// 123544151-43234324.  This method uses DES as the crypto provider and assumes also 
        /// that the cipher text is hexadecimal encodes.
        /// </summary>
        /// <param name="strData">The cipher text + the IV</param>
        /// <param name="strKey">The cipher key</param>
        /// <returns>The original plain text as an array of bytes</returns>
        public static byte[] DecryptToBytes(string strData,string strKey)
        {
            int ldx = strData.LastIndexOf(_MARKER);
            if (ldx < 1)
            {
                ldx = strData.LastIndexOf('-');
            }
            if (ldx < 1)
            {
                throw (new SecurityException("Missing IV from cipher text"));
            }
            string strIV = strData.Substring(ldx + 1);
            strData = strData.Substring(0,ldx);
            DES des = DESCryptoServiceProvider.Create();
            des.Mode = CipherMode.CBC;
            byte[] bytesKey = MakeCipherKey(strKey,des);
            byte[] bytesIV = BytesFromHexString(strIV);
            CryptoStream decStream = new CryptoStream(new MemoryStream(BytesFromHexString(strData)),
                des.CreateDecryptor(bytesKey,bytesIV),
                CryptoStreamMode.Read);
            MemoryStream ms = new MemoryStream();
            byte[] buf = new byte[4096];
            while (true)
            {
                int amt = decStream.Read(buf,0,buf.Length);
                if (amt < 1)
                {
                    break;
                }
                ms.Write(buf,0,amt);
            }
            return (ms.ToArray());
        }

        /// <summary>
        /// Decrypts the given string of cipher text with the given key string.  The IV for the
        /// cipher text is assumed to be appended to the cipher text after a MARKER character, e.g.
        /// 123544151-43234324.  This method uses DES as the crypto provider and assumes also 
        /// that the cipher text is hexadecimal encodes.
        /// </summary>
        /// <param name="strData">The cipher text + the IV</param>
        /// <param name="strKey">The cipher key</param>
        /// <returns>The original plain text as an array of bytes</returns>
        public static byte[] DecryptBase64ToBytes(string strData,string strKey)
        {
            int ldx = strData.LastIndexOf(_Base64MARKER);
            if (ldx < 1)
            {
                ldx = strData.LastIndexOf('-');
            }
            if (ldx < 1)
            {
                throw (new SecurityException("Missing IV from cipher text"));
            }
            string strIV = strData.Substring(ldx + 1);
            strData = strData.Substring(0,ldx);
            DES des = DESCryptoServiceProvider.Create();
            des.Mode = CipherMode.CBC;
            byte[] bytesKey = MakeCipherKey(strKey,des);
            byte[] bytesIV = Base64ToBytes(strIV);
            CryptoStream decStream = new CryptoStream(new MemoryStream(Base64ToBytes(strData)),
                des.CreateDecryptor(bytesKey,bytesIV),
                CryptoStreamMode.Read);
            MemoryStream ms = new MemoryStream();
            byte[] buf = new byte[4096];
            while (true)
            {
                int amt = decStream.Read(buf,0,buf.Length);
                if (amt < 1)
                {
                    break;
                }
                ms.Write(buf,0,amt);
            }
            return (ms.ToArray());
        }

        #endregion

        #region AES Decryption
        /// <summary>
        /// Decrypts the given data using the common key.
        /// </summary>
        /// <param name="strData"></param>
        /// <returns></returns>
        public static string DecryptAES(string strData)
        {
            if (strData == null)
            {
                return (null);
            }
            return (DecryptAES(strData, _COMMON_KEY));
        }
        public static string DecryptAESBase64(string strData)
        {
            if (strData == null)
            {
                return (null);
            }
            return (DecryptAESBase64(strData, _COMMON_KEY));
        }

        /// <summary>
        /// Decrypts the given data using the common key.
        /// </summary>
        /// <param name="strData"></param>
        /// <returns>The original plain text as a byte array.</returns>
        public static byte[] DecryptAESToBytes(string strData)
        {
            if (strData == null)
            {
                return (null);
            }
            return (DecryptAESToBytes(strData, _COMMON_KEY));
        }

        /// <summary>
        /// Decrypts the given data using the common key.
        /// </summary>
        /// <param name="strData"></param>
        /// <returns>The original plain text as a byte array.</returns>
        public static byte[] DecryptAESBase64ToBytes(string strData)
        {
            if (strData == null)
            {
                return (null);
            }
            return (DecryptAESBase64ToBytes(strData, _COMMON_KEY));
        }

        /// <summary>
        /// Decrypts the given string of cipher text with the given key string.  The IV for the
        /// cipher text is assumed to be appended to the cipher text after a MARKER character, e.g.
        /// 123544151-43234324.  This method uses DES as the crypto provider and assumes also 
        /// that the cipher text is hexadecimal encodes.
        /// </summary>
        /// <param name="strData">The cipher text + the IV</param>
        /// <param name="strKey">The cipher key</param>
        /// <returns>The plain text</returns>
        public static string DecryptAES(string strData, string strKey)
        {
            if (strData == null)
            {
                return (null);
            }
            byte[] plain = DecryptAESToBytes(strData, strKey);
            string strText = System.Text.Encoding.Default.GetString(plain);
            return (strText);
        }
        public static string DecryptAES(string strData, byte[] key)
        {
            if (strData == null)
            {
                return (null);
            }
            byte[] plain = DecryptAESToBytes(strData, key);
            string strText = System.Text.Encoding.Default.GetString(plain);
            return (strText);
        }
        public static string DecryptAESBase64(string strData, string strKey)
        {
            if (strData == null)
            {
                return (null);
            }
            byte[] plain = DecryptAESBase64ToBytes(strData, strKey);
            string strText = System.Text.Encoding.Default.GetString(plain);
            return (strText);
        }

        public static string DecryptAESBase64(string strData, byte[] bytesKey)
        {
            if (strData == null)
            {
                return (null);
            }
            byte[] plain = DecryptAESBase64ToBytes(strData, bytesKey);
            string strText = System.Text.Encoding.Default.GetString(plain);
            return (strText);
        }

        /// <summary>
        /// Decrypts the given string of cipher text with the given key string.  The IV for the
        /// cipher text is assumed to be appended to the cipher text after a MARKER character, e.g.
        /// 123544151-43234324.  This method uses DES as the crypto provider and assumes also 
        /// that the cipher text is hexadecimal encodes.
        /// </summary>
        /// <param name="strData">The cipher text + the IV</param>
        /// <param name="strKey">The cipher key</param>
        /// <returns>The original plain text as an array of bytes</returns>
        public static byte[] DecryptAESToBytes(string strData, string strKey)
        {
            if (strData == null)
            {
                return (null);
            }
            Aes des = AesCryptoServiceProvider.Create();
            des.Mode = CipherMode.CBC;
            byte[] bytesKey = MakeCipherKey(strKey, des);
            return (DecryptAESToBytes(strData, bytesKey));
        }

        /// <summary>
        /// Decrypts the given string of cipher text with the given key string.  The IV for the
        /// cipher text is assumed to be appended to the cipher text after a MARKER character, e.g.
        /// 123544151-43234324.  This method uses DES as the crypto provider and assumes also 
        /// that the cipher text is hexadecimal encodes.
        /// </summary>
        /// <param name="strData">The cipher text + the IV</param>
        /// <param name="strKey">The cipher key</param>
        /// <returns>The original plain text as an array of bytes</returns>
        public static byte[] DecryptAESToBytes(string strData, byte[] bytesKey)
        {
            if (strData == null)
            {
                return (null);
            }
            int ldx = strData.LastIndexOf(_MARKER);
            if (ldx < 1)
            {
                ldx = strData.LastIndexOf('-');
            }
            if (ldx < 1)
            {
                throw (new SecurityException("Missing IV from cipher text"));
            }
            string strIV = strData.Substring(ldx + 1);
            strData = strData.Substring(0, ldx);
            Aes des = AesCryptoServiceProvider.Create();
            des.Mode = CipherMode.CBC;
            byte[] bytesIV = BytesFromHexString(strIV);
            CryptoStream decStream = new CryptoStream(new MemoryStream(BytesFromHexString(strData)),
                des.CreateDecryptor(bytesKey, bytesIV),
                CryptoStreamMode.Read);
            MemoryStream ms = new MemoryStream();
            byte[] buf = new byte[4096];
            while (true)
            {
                int amt = decStream.Read(buf, 0, buf.Length);
                if (amt < 1)
                {
                    break;
                }
                ms.Write(buf, 0, amt);
            }
            return (ms.ToArray());
        }
        /// <summary>
        /// Decrypts the given string of cipher text with the given key string.  The IV for the
        /// cipher text is assumed to be appended to the cipher text after a MARKER character, e.g.
        /// 123544151-43234324.  This method uses DES as the crypto provider and assumes also 
        /// that the cipher text is hexadecimal encodes.
        /// </summary>
        /// <param name="strData">The cipher text + the IV</param>
        /// <param name="strKey">The cipher key</param>
        /// <returns>The original plain text as an array of bytes</returns>
        public static byte[] DecryptAESBase64ToBytes(string strData, string strKey)
        {
            if (strData == null)
            {
                return (null);
            }
            int ldx = strData.LastIndexOf(_Base64MARKER);
            if (ldx < 1)
            {
                ldx = strData.LastIndexOf('-');
            }
            if (ldx < 1)
            {
                throw (new SecurityException("Missing IV from cipher text"));
            }
            string strIV = strData.Substring(ldx + 1);
            strData = strData.Substring(0, ldx);
            Aes des = AesCryptoServiceProvider.Create();
            des.Mode = CipherMode.CBC;
            byte[] bytesKey = MakeCipherKey(strKey, des);
            byte[] bytesIV = Base64ToBytes(strIV);
            CryptoStream decStream = new CryptoStream(new MemoryStream(Base64ToBytes(strData)),
                des.CreateDecryptor(bytesKey, bytesIV),
                CryptoStreamMode.Read);
            MemoryStream ms = new MemoryStream();
            byte[] buf = new byte[4096];
            while (true)
            {
                int amt = decStream.Read(buf, 0, buf.Length);
                if (amt < 1)
                {
                    break;
                }
                ms.Write(buf, 0, amt);
            }
            return (ms.ToArray());
        }
        public static byte[] DecryptAESBase64ToBytes(string strData, byte[] bytesKey)
        {
            if (strData == null)
            {
                return (null);
            }
            int ldx = strData.LastIndexOf(_Base64MARKER);
            if (ldx < 1)
            {
                ldx = strData.LastIndexOf('-');
            }
            if (ldx < 1)
            {
                throw (new SecurityException("Missing IV from cipher text"));
            }
            string strIV = strData.Substring(ldx + 1);
            strData = strData.Substring(0, ldx);
            Aes des = AesCryptoServiceProvider.Create();
            des.Mode = CipherMode.CBC;
            byte[] bytesIV = Base64ToBytes(strIV);
            CryptoStream decStream = new CryptoStream(new MemoryStream(Base64ToBytes(strData)),
                des.CreateDecryptor(bytesKey, bytesIV),
                CryptoStreamMode.Read);
            MemoryStream ms = new MemoryStream();
            byte[] buf = new byte[4096];
            while (true)
            {
                int amt = decStream.Read(buf, 0, buf.Length);
                if (amt < 1)
                {
                    break;
                }
                ms.Write(buf, 0, amt);
            }
            return (ms.ToArray());
        }

        #endregion

        /// <summary>
        /// Takes a hex string and converts it to its byte equivalent.
        /// </summary>
        /// <param name="strHex"></param>
        /// <returns></returns>
        public static byte[] BytesFromHexString(string strHex)
        {
            string HexLookup = "0123456789ABCDEF";
            strHex = strHex.ToUpper();
            MemoryStream ms = new MemoryStream();
            for(int i=0; i < strHex.Length; i+=2) 
            {
                // Convert base 16 to binary                
                byte b = 0;
                int ival = HexLookup.IndexOf(strHex[i]);
                b = (byte)((ival << 4) & 0xF0);
                ival = HexLookup.IndexOf(strHex[i+1]);
                b |= (byte)(ival & 0x0F);
                ms.WriteByte(b);
            }
            byte[] bb = new byte[ms.Length];
            byte[] buf = ms.GetBuffer();
            for(int i=0; i < bb.Length; i++) 
            {
                bb[i] = buf[i];
            }
            return(bb);
        }

        /// <summary>
        /// Encodes the given byte array using Base64 encoding (not quoted-printable), and 
        /// returns a string of the base64 encoding.
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public static string Base64FromBytes(byte[] bytes, int length)
        {
			return(Convert.ToBase64String(bytes, 0, length));
        }

        /// <summary>
        /// Encodes the given byte array using Base64 encoding (not quoted-printable), and 
        /// returns a string of the base64 encoding.
        /// </summary>
        /// <param name="input">The original base64 string to decode</param>
        /// <returns>The decoded bytes.</returns>
        public static byte[] Base64ToBytes(string input)
        {
            return (Convert.FromBase64String(input));
        }

        /// <summary>
        /// Returns a hex encoded string from the given byte array.
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public static string HexStringFromBytes(byte[] bytes, int length)
        {
            string HexLookup = "0123456789ABCDEF";
            char[] cc = new char[length*2];
            int idx = 0;
            for(int i=0; i < length; i++) 
            {
                int ival = ((int)((bytes[i] & 0xF0) >> 4)) & 0xFF;
                cc[idx++] = HexLookup[ival];
                ival = ((int)(bytes[i] & 0x0F)) & 0xFF;
                cc[idx++] = HexLookup[ival];
            }
            return(new string(cc));
        }

        #region DES Encryption
        /// <summary>
		/// Uses the common key to encrypt the given data.
		/// </summary>
		/// <param name="strData"></param>
		/// <returns></returns>
		public static string Encrypt(string strData)
		{
			return(Encrypt(strData, _COMMON_KEY));
		}

        /// <summary>
        /// Encrypts the given byte array using the given key. The resulting
        /// cipher text is then converted to base-64 encoding.
        /// </summary>
        /// <param name="data">Data to be encrypted.</param>
        /// <returns>base-16 encoded data of the given byte array.</returns>
        public static string Encrypt(byte[] data)
        {
            return (Encrypt(data,_COMMON_KEY));
        }

        /// <summary>
        /// Encrypts the given byte array using the given key. The resulting
        /// cipher text is then converted to base-64 encoding.
        /// </summary>
        /// <param name="data">Data to be encrypted.</param>
        /// <returns>base-64 encoded data of the given byte array.</returns>
        public static string EncryptBase64(byte[] data)
        {
            return (EncryptBase64(data,_COMMON_KEY));
        }

        /// Encrypts the given byte array using the given key. The resulting
        /// cipher text is then converted to base-64 encoding.
        /// </summary>
        /// <param name="bytesPlain"></param>
        /// <param name="strKey"></param>
        /// <returns>base-64 encoded data of the given byte array.</returns>
        public static string EncryptBase64(byte[] bytesPlain,string strKey)
        {
            DES des = DESCryptoServiceProvider.Create();
            des.Mode = CipherMode.CBC;
            byte[] bytesKey = MakeCipherKey(strKey,des);
            des.GenerateIV();
            byte[] bytesIV = des.IV;
            StringBuilder sb = new StringBuilder();
            MemoryStream ms = new MemoryStream();
            CryptoStream encStream = new CryptoStream(ms,des.CreateEncryptor(bytesKey,bytesIV),CryptoStreamMode.Write);
            // Encrypt the data using default encoding
            int remainder = bytesPlain.Length % des.BlockSize;
            byte[] bytesToEncrypt = new byte[bytesPlain.Length + remainder];
            bytesPlain.CopyTo(bytesToEncrypt,0);
            encStream.Write(bytesToEncrypt,0,bytesPlain.Length);
            encStream.FlushFinalBlock();
            encStream.Close();
            byte[] cryptText = ms.ToArray();
            sb.Append(Base64FromBytes(cryptText,cryptText.Length));
            sb.Append(_Base64MARKER);
            sb.Append(Base64FromBytes(bytesIV,bytesIV.Length));
            return (sb.ToString());
        }

        /// Encrypts the given byte array using the given key. The resulting
        /// cipher text is then converted to base-64 encoding.
        /// </summary>
        /// <param name="bytesPlain"></param>
        /// <param name="strKey"></param>
        /// <returns></returns>
        public static string Encrypt(byte[] bytesPlain, string strKey)
        {
            DES des = DESCryptoServiceProvider.Create();
            des.Mode = CipherMode.CBC;
            byte[] bytesKey = MakeCipherKey(strKey,des);
            des.GenerateIV();
            byte[] bytesIV = des.IV;
            StringBuilder sb = new StringBuilder();
            MemoryStream ms = new MemoryStream();
            CryptoStream encStream = new CryptoStream(ms,des.CreateEncryptor(bytesKey,bytesIV),CryptoStreamMode.Write);
            // Encrypt the data using default encoding
            int remainder = bytesPlain.Length % des.BlockSize;
            byte[] bytesToEncrypt = new byte[bytesPlain.Length + remainder];
            bytesPlain.CopyTo(bytesToEncrypt,0);
            encStream.Write(bytesToEncrypt,0,bytesPlain.Length);
            encStream.FlushFinalBlock();
            encStream.Close();
            byte[] cryptText = ms.ToArray();
            sb.Append(HexStringFromBytes(cryptText,cryptText.Length));
            sb.Append(_MARKER);
            sb.Append(HexStringFromBytes(bytesIV,bytesIV.Length));
            return (sb.ToString());
        }

        /// <summary>
        /// Encrypts data in the given argument and returns the result as a hex encoded
        /// string.
        /// </summary>
        /// <param name="strData"></param>
        /// <param name="strKey"></param>
        /// <returns></returns>
        public static string Encrypt(string strData, string strKey)
        {
            // Encrypt the data using default encoding
            byte[] bytesPlain = Encoding.Default.GetBytes(strData);
            return(Encrypt(bytesPlain,strKey));
        }

        #endregion

        #region AES Encryption
        /// <summary>
        /// Encrypts data in the given argument and returns the result as a hex encoded
        /// string.
        /// </summary>
        /// <param name="strData"></param>
        /// <param name="strKey"></param>
        /// <returns></returns>
        public static string EncryptAES(string strData, string strKey)
        {
            if (strData == null)
            {
                return (null);
            }
            // Encrypt the data using default encoding
            byte[] bytesPlain = Encoding.Default.GetBytes(strData);
            return(EncryptAES(bytesPlain,strKey));
        }
        public static string EncryptAES(string strData, byte[] key)
        {
            if (strData == null)
            {
                return (null);
            }
            // Encrypt the data using default encoding
            byte[] bytesPlain = Encoding.Default.GetBytes(strData);
            return (EncryptAES(bytesPlain, key));
        }
        public static string EncryptAESBase64(string strData, string strKey)
        {
            if (strData == null)
            {
                return (null);
            }
            // Encrypt the data using default encoding
            byte[] bytesPlain = Encoding.Default.GetBytes(strData);
            return (EncryptAESBase64(bytesPlain, strKey));
        }
        public static string EncryptAESBase64(string strData, byte[] bytesKey)
        {
            if (strData == null)
            {
                return (null);
            }
            // Encrypt the data using default encoding
            byte[] bytesPlain = Encoding.Default.GetBytes(strData);
            return (EncryptAESBase64(bytesPlain, bytesKey));
        }

        /// Encrypts the given byte array using the given key. The resulting
        /// cipher text is then converted to base-64 encoding.
        /// </summary>
        /// <param name="bytesPlain"></param>
        /// <param name="strKey"></param>
        /// <returns></returns>
        public static string EncryptAES(byte[] bytesPlain, string strKey)
        {
            if (bytesPlain == null)
            {
                return (null);
            }
            Aes des = AesCryptoServiceProvider.Create();
            des.Mode = CipherMode.CBC;
            byte[] bytesKey = MakeCipherKey(strKey, des);
            return (EncryptAES(bytesPlain, bytesKey));
        }
        public static string EncryptAES(byte[] bytesPlain, byte[] bytesKey)
        {
            if (bytesPlain == null)
            {
                return (null);
            }
            Aes des = AesCryptoServiceProvider.Create();
            des.Mode = CipherMode.CBC;
            des.GenerateIV();
            byte[] bytesIV = des.IV;
            StringBuilder sb = new StringBuilder();
            MemoryStream ms = new MemoryStream();
            CryptoStream encStream = new CryptoStream(ms, des.CreateEncryptor(bytesKey, bytesIV), CryptoStreamMode.Write);
            // Encrypt the data using default encoding
            int remainder = bytesPlain.Length % des.BlockSize;
            byte[] bytesToEncrypt = new byte[bytesPlain.Length + remainder];
            bytesPlain.CopyTo(bytesToEncrypt, 0);
            encStream.Write(bytesToEncrypt, 0, bytesPlain.Length);
            encStream.FlushFinalBlock();
            encStream.Close();
            byte[] cryptText = ms.ToArray();
            sb.Append(HexStringFromBytes(cryptText, cryptText.Length));
            sb.Append(_MARKER);
            sb.Append(HexStringFromBytes(bytesIV, bytesIV.Length));
            return (sb.ToString());
        }
        /// Encrypts the given byte array using the given key. The resulting
        /// cipher text is then converted to base-64 encoding.
        /// </summary>
        /// <param name="bytesPlain"></param>
        /// <param name="strKey"></param>
        /// <returns>base-64 encoded data of the given byte array.</returns>
        public static string EncryptAESBase64(byte[] bytesPlain,string strKey)
        {
            if (bytesPlain == null)
            {
                return (null);
            }
            Aes des = AesCryptoServiceProvider.Create();
            des.Mode = CipherMode.CBC;
            byte[] bytesKey = MakeCipherKey(strKey,des);
            des.GenerateIV();
            byte[] bytesIV = des.IV;
            StringBuilder sb = new StringBuilder();
            MemoryStream ms = new MemoryStream();
            CryptoStream encStream = new CryptoStream(ms,des.CreateEncryptor(bytesKey,bytesIV),CryptoStreamMode.Write);
            // Encrypt the data using default encoding
            int remainder = bytesPlain.Length % des.BlockSize;
            byte[] bytesToEncrypt = new byte[bytesPlain.Length + remainder];
            bytesPlain.CopyTo(bytesToEncrypt,0);
            encStream.Write(bytesToEncrypt,0,bytesPlain.Length);
            encStream.FlushFinalBlock();
            encStream.Close();
            byte[] cryptText = ms.ToArray();
            sb.Append(Base64FromBytes(cryptText,cryptText.Length));
            sb.Append(_Base64MARKER);
            sb.Append(Base64FromBytes(bytesIV,bytesIV.Length));
            return (sb.ToString());
        }
        public static string EncryptAESBase64(byte[] bytesPlain, byte[] bytesKey)
        {
            if (bytesPlain == null)
            {
                return (null);
            }
            Aes des = AesCryptoServiceProvider.Create();
            des.Mode = CipherMode.CBC;
            des.GenerateIV();
            byte[] bytesIV = des.IV;
            StringBuilder sb = new StringBuilder();
            MemoryStream ms = new MemoryStream();
            CryptoStream encStream = new CryptoStream(ms, des.CreateEncryptor(bytesKey, bytesIV), CryptoStreamMode.Write);
            // Encrypt the data using default encoding
            int remainder = bytesPlain.Length % des.BlockSize;
            byte[] bytesToEncrypt = new byte[bytesPlain.Length + remainder];
            bytesPlain.CopyTo(bytesToEncrypt, 0);
            encStream.Write(bytesToEncrypt, 0, bytesPlain.Length);
            encStream.FlushFinalBlock();
            encStream.Close();
            byte[] cryptText = ms.ToArray();
            sb.Append(Base64FromBytes(cryptText, cryptText.Length));
            sb.Append(_Base64MARKER);
            sb.Append(Base64FromBytes(bytesIV, bytesIV.Length));
            return (sb.ToString());
        }
        /// <summary>
        /// Encrypts the given byte array using the given key. The resulting
        /// cipher text is then converted to base-64 encoding.
        /// </summary>
        /// <param name="data">Data to be encrypted.</param>
        /// <returns>base-64 encoded data of the given byte array.</returns>
        public static string EncryptAESBase64(byte[] data)
        {
            return (EncryptAESBase64(data,_COMMON_KEY));
        }
        /// <summary>
		/// Uses the common key to encrypt the given data.
		/// </summary>
		/// <param name="strData"></param>
		/// <returns></returns>
		public static string EncryptAES(string strData)
		{
			return(EncryptAES(strData, _COMMON_KEY));
		}

        public static string EncryptAESBase64(string strData)
        {
            return (EncryptAESBase64(strData, _COMMON_KEY));
        }

        /// <summary>
        /// Encrypts the given byte array using the given key. The resulting
        /// cipher text is then converted to base-64 encoding.
        /// </summary>
        /// <param name="data">Data to be encrypted.</param>
        /// <returns>base-16 encoded data of the given byte array.</returns>
        public static string EncryptAES(byte[] data)
        {
            return (EncryptAES(data,_COMMON_KEY));
        }

#endregion

        #region DES Data Wrapping Methods
        public static string UnwrapData(string src, string key = null)
        {
            if (key == null)
            {
                key = _COMMON_KEY;
            }
            // 1. Decrypt the data
            string plain = Crypto.Decrypt(src, key);
            byte[] data = null;
            // 2. Try to decode the base-64
            try
            {
                data = Convert.FromBase64String(plain);
            }
            catch (FormatException ex)
            {
                // Not in base 64, so return it
                return (plain);
            }
            // 3. Uncompress
            MemoryStream ms = new MemoryStream(data);
            GZipStream gis = new GZipStream(ms, CompressionMode.Decompress);
            StreamReader sr = new StreamReader(gis);
            plain = sr.ReadToEnd();
            return (plain);
        }

        public static byte[] UnwrapDataToBytes(string src, string key = null)
        {
            if (key == null)
            {
                key = _COMMON_KEY;
            }
            // 1. Decrypt the data
            string plain = Crypto.Decrypt(src);
            byte[] data = null;
            // 2. Try to decode the base-64
            try
            {
                data = Convert.FromBase64String(plain);
            }
            catch (FormatException ex)
            {
                // Not in base 64, so return it
                return (data);
            }
            // 3. Uncompress
            MemoryStream ms = new MemoryStream(data);
            GZipStream gis = new GZipStream(ms, CompressionMode.Decompress);
            MemoryStream ms2 = new MemoryStream();
            byte[] buf = new byte[4096];
            while (gis.CanRead)
            {
                int amt = gis.Read(buf, 0, buf.Length);
                if (amt < 1)
                {
                    break;
                }
                ms2.Write(buf, 0, amt);
            }
            data = ms2.ToArray();
            return (data);
        }

        public static string WrapData(byte[] src, string key = null)
        {
            if (key == null)
            {
                key = _COMMON_KEY;
            }
            string str = null;
            // 1. Compress the data
            MemoryStream ms = new MemoryStream();
            GZipStream gos = new GZipStream(ms, CompressionMode.Compress);
            gos.Write(src, 0, src.Length);
            gos.Flush();
            byte[] data = ms.ToArray();
            // 2. Base 64 encode
            str = Convert.ToBase64String(data);
            // 3. Encrypt the data
            string crypto = Crypto.Encrypt(str);
            return (crypto);
        }

        public static string WrapData(string src, string key = null)
        {
            if (key == null)
            {
                key = _COMMON_KEY;
            }
            string str = src;
            // 1. Compress the data
            MemoryStream ms = new MemoryStream();
            GZipStream gos = new GZipStream(ms, CompressionMode.Compress);
            StreamWriter sw = new StreamWriter(gos);
            sw.Write(src);
            sw.Flush();
            gos.Flush();
            byte[] data = ms.ToArray();
            // 2. Base 64 encode
            str = Convert.ToBase64String(data);
            // 3. Encrypt the data
            string crypto = Crypto.Encrypt(str);
            return (crypto);
        }

        #endregion

        #region AES Data Wrapping Methods

        public static string WrapAESData(byte[] src, string key = null)
        {
            if (key == null)
            {
                key = _COMMON_KEY;
            }
            string str = null;
            // 1. Compress the data
            MemoryStream ms = new MemoryStream();
            GZipStream gos = new GZipStream(ms, CompressionMode.Compress);
            gos.Write(src, 0, src.Length);
            gos.Flush();
            gos.Close();
            byte[] data = ms.ToArray();
            // 2. Base 64 encode
            str = Convert.ToBase64String(data);
            // 3. Encrypt the data
            string crypto = Crypto.EncryptAES(str, key);
            return (crypto);
        }
        public static string WrapAESData(byte[] src, byte[] key)
        {
            string str = null;
            // 1. Compress the data
            MemoryStream ms = new MemoryStream();
            GZipStream gos = new GZipStream(ms, CompressionMode.Compress);
            gos.Write(src, 0, src.Length);
            gos.Flush();
            gos.Close();
            byte[] data = ms.ToArray();
            // 2. Base 64 encode
            str = Convert.ToBase64String(data);
            // 3. Encrypt the data
            string crypto = Crypto.EncryptAES(str, key);
            return (crypto);
        }
        public static string WrapAESData(Stream src, byte[] key)
        {
            string str = null;
            // 1. Compress the data
            MemoryStream ms = new MemoryStream();
            GZipStream gos = new GZipStream(ms, CompressionMode.Compress);
            src.CopyTo(gos);
            gos.Flush();
            gos.Close();
            byte[] data = ms.ToArray();
            // 2. Base 64 encode
            str = Convert.ToBase64String(data);
            // 3. Encrypt the data
            string crypto = Crypto.EncryptAES(str, key);
            return (crypto);
        }
        public static string WrapAESData(string src, byte[] key)
        {
            string str = src;
            // 1. Compress the data
            MemoryStream ms = new MemoryStream();
            GZipStream gos = new GZipStream(ms, CompressionMode.Compress);
            StreamWriter sw = new StreamWriter(gos);
            sw.Write(src);
            sw.Flush();
            gos.Flush();
            sw.Close();
            byte[] data = ms.ToArray();
            // 2. Base 64 encode
            str = Convert.ToBase64String(data);
            // 3. Encrypt the data
            string crypto = Crypto.EncryptAES(str, key);
            return (crypto);
        }
        public static string WrapAESData(string src, string key = null)
        {
            if (key == null)
            {
                key = _COMMON_KEY;
            }
            string str = src;
            // 1. Compress the data
            MemoryStream ms = new MemoryStream();
            GZipStream gos = new GZipStream(ms, CompressionMode.Compress);
            StreamWriter sw = new StreamWriter(gos);
            sw.Write(src);
            sw.Flush();
            gos.Flush();
            sw.Close();
            byte[] data = ms.ToArray();
            // 2. Base 64 encode
            str = Convert.ToBase64String(data);
            // 3. Encrypt the data
            string crypto = Crypto.EncryptAES(str, key);
            return (crypto);
        }

        public static string UnwrapAESData(string src, byte[] key)
        {
            // 1. Decrypt the data
            string plain = Crypto.DecryptAES(src, key);
            byte[] data = null;
            // 2. Try to decode the base-64
            try
            {
                data = Convert.FromBase64String(plain);
            }
            catch (FormatException ex)
            {
                // Not in base 64, so return it
                return (plain);
            }
            // 3. Uncompress
            MemoryStream ms = new MemoryStream(data);
            GZipStream gis = new GZipStream(ms, CompressionMode.Decompress);
            StreamReader sr = new StreamReader(gis);
            plain = sr.ReadToEnd();
            return (plain);
        }

        public static string UnwrapAESData(string src, string key = null)
        {
            if (key == null)
            {
                key = _COMMON_KEY;
            }
            // 1. Decrypt the data
            string plain = Crypto.DecryptAES(src, key);
            byte[] data = null;
            // 2. Try to decode the base-64
            try
            {
                data = Convert.FromBase64String(plain);
            }
            catch (FormatException ex)
            {
                // Not in base 64, so return it
                return (plain);
            }
            // 3. Uncompress
            MemoryStream ms = new MemoryStream(data);
            GZipStream gis = new GZipStream(ms, CompressionMode.Decompress);
            StreamReader sr = new StreamReader(gis);
            plain = sr.ReadToEnd();
            return (plain);
        }
        public static byte[] UnwrapAESDataToBytes(string src, string key = null)
        {
            if (key == null)
            {
                key = _COMMON_KEY;
            }
            // 1. Decrypt the data
            string plain = Crypto.DecryptAES(src, key);
            byte[] data = null;
            // 2. Try to decode the base-64
            try
            {
                data = Convert.FromBase64String(plain);
            }
            catch (FormatException ex)
            {
                // Not in base 64, so return it
                return (data);
            }
            // 3. Uncompress
            MemoryStream ms = new MemoryStream(data);
            GZipStream gis = new GZipStream(ms, CompressionMode.Decompress);
            MemoryStream ms2 = new MemoryStream();
            byte[] buf = new byte[4096];
            while (gis.CanRead)
            {
                int amt = gis.Read(buf, 0, buf.Length);
                if (amt < 1)
                {
                    break;
                }
                ms2.Write(buf, 0, amt);
            }
            data = ms2.ToArray();
            return (data);
        }
        public static byte[] UnwrapAESDataToBytes(string src, byte[] key)
        {
            // 1. Decrypt the data
            string plain = Crypto.DecryptAES(src, key);
            byte[] data = null;
            // 2. Try to decode the base-64
            try
            {
                data = Convert.FromBase64String(plain);
            }
            catch (FormatException ex)
            {
                // Not in base 64, so return it
                return (data);
            }
            // 3. Uncompress
            MemoryStream ms = new MemoryStream(data);
            GZipStream gis = new GZipStream(ms, CompressionMode.Decompress);
            MemoryStream ms2 = new MemoryStream();
            byte[] buf = new byte[4096];
            while (gis.CanRead)
            {
                int amt = gis.Read(buf, 0, buf.Length);
                if (amt < 1)
                {
                    break;
                }
                ms2.Write(buf, 0, amt);
            }
            data = ms2.ToArray();
            return (data);
        }
        #endregion
	}
}
