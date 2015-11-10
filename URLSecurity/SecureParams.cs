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
using System.Collections.Generic;
using System.Configuration;
using System.Security;
using System.Text;

namespace OpenDMD.URLSecurity
{
    /// <summary>
    /// This class is used to decrypt the external query parameters
    /// </summary>
    public partial class SecureParams
    {
        private Dictionary<string, string> _hashParams = new Dictionary<string, string>();
        private bool _ReadOnly = true;
        private static readonly string DEFAULT_KEY_NAME = "URI.Key";
        private static readonly string URL_ID_KEY = "_url_id";
        private static readonly string CRYPTO_PREFIX = "%%";

        public SecureParams()
        {
            _ReadOnly = false;
        }

        public SecureParams(int url_id)
        {
            _ReadOnly = false;
            this[URL_ID_KEY] = url_id.ToString();
            _ReadOnly = true;
        }

        /// <summary>
        /// Assumes the params are encrypted and externalized as hexadecimal
        /// values.  The ciphertext is the first character string before the last
        /// '-' character, and the string after the '-' is used for decryption
        /// purposes.
        /// </summary>
        /// <param name="strParam"></param>
        public SecureParams(string strParam)
        {
            string strKey = ConfigurationManager.AppSettings[DEFAULT_KEY_NAME];
            if (string.IsNullOrEmpty(strKey))
            {
                throw (new SecurityException("Secure params encryption key is not defined."));
            }
			if(strKey.StartsWith(CRYPTO_PREFIX)) {
				strKey = Crypto.Decrypt(strKey);
			}
            string strText = Crypto.Decrypt(strParam, strKey);
            // Parse the params from the query string
            ParseParams(strText);
        }

        public SecureParams(string strParam, string strKey = null)
        {
            if(strKey == null) {
                strKey = ConfigurationManager.AppSettings[DEFAULT_KEY_NAME];
                if (string.IsNullOrEmpty(strKey))
                {
                    throw (new SecurityException("Encryption key is not defined."));
                }
				if(strKey.StartsWith(CRYPTO_PREFIX)) {
					strKey = Crypto.Decrypt(strKey);
				}
            }
            string strText = Crypto.Decrypt(strParam, strKey);
            // Parse the params from the query string
            ParseParams(strText);
        }

        /// <summary>
        /// Copy the contents of the given parameters into this instance.
        /// </summary>
        /// <param name="sp"></param>
        public void Copy(SecureParams sp)
        {
            foreach (string key in sp._hashParams.Keys)
            {
                _hashParams[key] = sp._hashParams[key];
            }
        }

        #region URL Safety
        /// <summary>
        /// Removes the HEX-code markup in the given string, replacing it
        /// with character equivalents of the HEX code.
        /// </summary>
        /// <param name="str">The string to decode</param>
        /// <returns></returns>
        public static string UrlDecode(string str)
        {
            if(str == null) 
            {
                return(null);
            }
            StringBuilder sb = new StringBuilder();
            for(int i=0; i < str.Length; i++) 
            {
                char cc = str[i];
                if(cc == '%' && (i <= str.Length - 3)) 
                {
                    int idx = 0;
                    sb.Append(Uri.HexUnescape(str.Substring(i, 3), ref idx));
                    i += 2;
                }
                else 
                {
                    sb.Append(cc);
                }
            }
            return(sb.ToString());
        }

        /// <summary>
        /// Encodes the given string to be printable in a URL
        /// </summary>
        /// <param name="str">The string to make URL-printable</param>
        /// <returns></returns>
        public static string UrlEncode(string str)
        {
            if(str == null) 
            {
                return(null);
            }
            StringBuilder sb = new StringBuilder();
            for(int i=0; i < str.Length; i++) 
            {
                char cc = str[i];
                if(cc <= ' ' || Char.IsControl(cc) || cc == '%' || cc == '&' || cc == '?') 
                {
                    sb.Append(Uri.HexEscape(cc));
                }
                else 
                {
                    sb.Append(cc);
                }
            }
            return(sb.ToString());
        }

        #endregion

        /// <summary>
        /// Parses out words from the given text that are delineated by the '&' character.
        /// Assumes that each parameter extracted has a value associatd with it that
        /// is identified by the '=' separator character.
        /// </summary>
        /// <param name="strText"></param>
        private void ParseParams(string strText)
        {
            string[] p = strText.Split('&');
            for(int i=0; i < p.Length; i++) 
            {
                string[] v = p[i].Split('=');
                if(v.Length == 2) 
                {
                    _hashParams[v[0]] = v[1];
                }
            }
        }

        /// <summary>
        /// Encrypts the contents of the query parameters and returns
        /// the encrypted text, which is an encrypted version of a
        /// query parameter list: name=value&name=value&... Each of
        /// the values is UrlEncoded using HEX encoding.
        /// </summary>
        /// <returns>The encrypted text for these parameters</returns>
        public string Encrypt()
        {
            return (Encrypt(DEFAULT_KEY_NAME));
        }

        /// <summary>
        /// Encrypts the contents of the query parameters and returns
        /// the encrypted text, which is an encrypted version of a
        /// query parameter list: name=value&name=value&... Each of
        /// the values is UrlEncoded using HEX encoding.
        /// </summary>
        /// <param name="keyName">The name of the key to use for encryption</param>
        /// <returns></returns>
        public string Encrypt(string keyName)
        {
            string strKey = ConfigurationManager.AppSettings[keyName];
            if (strKey == null || strKey.Length == 0)
            {
                throw (new SecurityException("Encryption key is not defined."));
            }
            return (EncryptWithKey(strKey));
        }

        /// <summary>
        /// Encrypts the given query with the AFF.JobKey key.
        /// </summary>
        /// <param name="strQuery">The query to encrypt</param>
        /// <returns>An encrypted string using the Crypto class.</returns>
        public static string EncryptParams(string strQuery)
        {
            return (EncryptParams(strQuery, DEFAULT_KEY_NAME));
        }
        /// <summary>
        /// Encrypts the given query with a key from the app configuration.
        /// </summary>
        /// <param name="strQuery">The query to encrypt</param>
        /// <returns>An encrypted string using the Crypto class.</returns>
        public static string EncryptParams(string strQuery, string keyName)
        {
            string strKey = ConfigurationManager.AppSettings[keyName];
            if(strKey == null || strKey.Length == 0) 
            {
                throw(new SecurityException("Encryption key is not defined."));
            }
            return(EncryptParamsWithKey(strQuery, strKey)); 
        }

        public string EncryptWithKey(string keyValue)
        {
            StringBuilder sb = new StringBuilder();
            char sep = '\0';
            foreach (string key in _hashParams.Keys)
            {
                if (sep != '\0')
                {
                    sb.Append(sep);
                }
                sb.Append(key);
                sb.Append('=');
                sb.Append(UrlEncode(_hashParams[key] as string));
                sep = '&';
            }
            return (EncryptParamsWithKey(sb.ToString(), keyValue));
        }
        public static string EncryptParamsWithKey(string strQuery, string keyValue)
        {
            return (Crypto.Encrypt(strQuery, keyValue));
        }

        /// <summary>
        /// Returns the URL decoded value for the given parameter key.
        /// </summary>
        public string this[string strKey]
        {
            get 
            {
                if (_hashParams.ContainsKey(strKey))
                {
                    return (UrlDecode(_hashParams[strKey] as string));
                }
                return (null);
            }
            set 
            {
                if(_ReadOnly) 
                {
                    throw(new InvalidOperationException("Can not set values on a read-only secure query."));
                }
                if (value == null)
                {
                    _hashParams.Remove(strKey);
                }
                else
                {
                    _hashParams[strKey] = value;
                }
            }
        }
    }
}
