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
using System.Configuration;
using System.Security;
using System.Data.SqlClient;

namespace OpenDMD.URLSecurity
{
    /// <summary>
    /// Herein are the SQL specific support members for the SecureParams class.
    /// </summary>
    public partial class SecureParams
    {

        public void Invalidate()
        {
            if (_hashParams.ContainsKey(URL_ID_KEY))
            {
                using (SqlCommand cmd = new SqlCommand("update url_params set expiration=@1 where id=@2"))
                {
                    cmd.Parameters.AddWithValue("@2", _hashParams[URL_ID_KEY]);
                    cmd.Parameters.AddWithValue("@1", DateTime.Now.AddMinutes(-1));
                    DBHelper.Instance.NonQuery(cmd);
                }
            }
        }

        public void ExtendTime(int minutes = 5)
        {
            if (_hashParams.ContainsKey(URL_ID_KEY))
            {
                using (SqlCommand cmd = new SqlCommand("update url_params set expiration=@1 where id=@2"))
                {
                    cmd.Parameters.AddWithValue("@2", _hashParams[URL_ID_KEY]);
                    cmd.Parameters.AddWithValue("@1", DateTime.Now.AddMinutes(minutes));
                    DBHelper.Instance.NonQuery(cmd);
                }
            }
        }

        public int SaveToDB(string strKey = null)
        {
            if (strKey == null)
            {
                strKey = ConfigurationManager.AppSettings[DEFAULT_KEY_NAME];
                if (string.IsNullOrEmpty(strKey))
                {
                    throw (new SecurityException("Encryption key is not defined."));
                }
				if(strKey.StartsWith(CRYPTO_PREFIX)) {
					strKey = Crypto.Decrypt(strKey);
				}
            }
            string paramValue = EncryptWithKey(strKey);
            using (SqlCommand cmd = new SqlCommand("insert into url_params(params, expiration) values (@1, @2); select SCOPE_IDENTITY();"))
            {
                cmd.Parameters.AddWithValue("@1", paramValue);
                cmd.Parameters.AddWithValue("@2", DateTime.Now.AddMinutes(5));
                object obj = DBHelper.Instance.Scalar(cmd);
                if (obj != null && obj != DBNull.Value)
                {
                    return (int.Parse(obj.ToString()));
                }
            }
            return (-1);
        }

        public static void ExpireInDB(string paramValues, string strKey = null)
        {
            if (strKey == null)
            {
                strKey = ConfigurationManager.AppSettings[DEFAULT_KEY_NAME];
                if (string.IsNullOrEmpty(strKey))
                {
                    throw (new SecurityException("Encryption key is not defined."));
                }
				if(strKey.StartsWith(CRYPTO_PREFIX)) {
					strKey = Crypto.Decrypt(strKey);
				}
            }
            SecureParams sp = new SecureParams(paramValues, strKey);
            string sid = sp[URL_ID_KEY];
            if (string.IsNullOrEmpty(sid))
            {
                return;
            }
            try
            {
                using (SqlCommand cmd = new SqlCommand("update url_params set expiration=getdate()-1 where id=@1"))
                {
                    cmd.Parameters.AddWithValue("@1", sid);
                    DBHelper.Instance.NonQuery(cmd);
                }
            }
            catch (Exception ex)
            {
                // TODO: handle exceptions
            }
        }

        public static SecureParams FromDB(string paramValues, string strKey = null)
        {
            if (strKey == null)
            {
                strKey = ConfigurationManager.AppSettings[DEFAULT_KEY_NAME];
                if (string.IsNullOrEmpty(strKey))
                {
                    throw (new SecurityException("Encryption key is not defined."));
                }
				if(strKey.StartsWith(CRYPTO_PREFIX)) {
					strKey = Crypto.Decrypt(strKey);
				}
            }
            SecureParams sp = new SecureParams(paramValues, strKey);
            string sid = sp[URL_ID_KEY];
            if (string.IsNullOrEmpty(sid))
            {
                return (sp);
            }
            try
            {
                using (SqlCommand cmd = new SqlCommand("select params from url_params (nolock) where id=@1 and expiration > getdate()"))
                {
                    cmd.Parameters.AddWithValue("@1", sid);
                    object obj = DBHelper.Instance.Scalar(cmd);
                    if (obj != null && obj != DBNull.Value)
                    {
                        sp = new SecureParams(obj.ToString(), strKey);
                        return (sp);
                    }
                }
            }
            catch (Exception ex)
            {
                // TODO: Handle exceptions
            }
            return (null);
        }
    }
}
