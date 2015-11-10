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
using System.Data;
using System.Data.SqlClient;
using System.Threading;
using System.Diagnostics;

namespace OpenDMD.URLSecurity
{
    /// <summary>
    /// Provides methods to help in making connections to the Microsoft SQL server.
    /// </summary>
    public class DBHelper
    {
        /// <summary>
        /// The maximum number of connection attempts before failure
        /// </summary>
        private int _MaxAttempts = 3;
        /// <summary>
        ///  Delay time between connection attempts in milliseconds
        /// </summary>
        private int _AttemptDelay = 500;

        private static DBHelper _Instance = new DBHelper();

        private DBHelper()
        {
            string s = ConfigurationManager.AppSettings["DB.MaxAttempts"];
            if (s != null)
            {
                try
                {
                    _MaxAttempts = int.Parse(s);
                }
                catch (Exception)
                {
                }
            }
            s = ConfigurationManager.AppSettings["DB.AttemptDelay"];
            if (s != null)
            {
                try
                {
                    _AttemptDelay = int.Parse(s);
                }
                catch (Exception)
                {
                }
            }
        }

        public static DBHelper Instance
        {
            get
            {
                return (_Instance);
            }
        }

        public string SafeConnectionString
        {
            get; set;
        }

        #region Connection Handling

        /// <summary>
        /// Runs the given command as a data query. Errors with a severity of 17 or greater are retried.
        /// </summary>
        /// <param name="cmd"></param>
        /// <returns></returns>
        public DataSet Query(SqlCommand cmd)
        {
            if (string.IsNullOrEmpty(SafeConnectionString))
            {
                throw (new ArgumentNullException("SafeConnectionString", "Please set the connection string for the helper to use."));
            }
            int attempt = _MaxAttempts;
            SqlException lastEx = null;
            while (attempt > 0)
            {
                try
                {
                    using (SqlConnection con = new SqlConnection(SafeConnectionString))
                    {
                        con.Open();
                        cmd.Connection = con;
                        SqlDataAdapter adapter = new SqlDataAdapter(cmd);
                        DataSet ds = new DataSet();
                        adapter.Fill(ds);
                        return (ds);
                    }
                }
                catch (SqlException ex)
                {
                    lastEx = ex;
                    if (ex.Class >= 17 && ex.Class < 20)  // http://msdn.microsoft.com/en-us/library/ms164086.aspx
                    {
                        attempt--;
                        if (_AttemptDelay > 0 && attempt > 0)
                        {
                            try
                            {
                                Thread.Sleep(_AttemptDelay);
                            }
                            catch (Exception)
                            {
                                //Application Exception
                            }
                        }
                    }
                    else
                    {
                        if (ex.Class == 15) // SQL statement syntax error
                        {
                            Trace.WriteLine("[15] Bad SQL statement: " + cmd.CommandText);
                        }
                        else if (ex.Class == 14) // SQL permission error
                        {
                            Trace.WriteLine("[14] Missing SQL permissions for statement: " + cmd.CommandText);
                        }
                        else if (ex.Class == 11) // SQL object missing error
                        {
                            Trace.WriteLine("[11] Missing SQL object for statement: " + cmd.CommandText);
                        }
                        break;
                    }
                }
            }
            if (lastEx != null)
            {
                throw (lastEx);
            }
            throw (new Exception("Failed to make connection to the database."));
        }

        /// <summary>
        /// Runs the given command as a non-query.
        /// </summary>
        /// <param name="cmd"></param>
        /// <returns></returns>
        public int NonQuery(SqlCommand cmd)
        {
            if (string.IsNullOrEmpty(SafeConnectionString))
            {
                throw (new ArgumentNullException("SafeConnectionString", "Please set the connection string for the helper to use."));
            }
            int attempt = _MaxAttempts;
            SqlException lastEx = null;
            while (attempt > 0)
            {
                try
                {
                    using (SqlConnection con = new SqlConnection(SafeConnectionString))
                    {
                        con.Open();
                        cmd.Connection = con;
                        return (cmd.ExecuteNonQuery());
                    }
                }
                catch (SqlException ex)
                {
                    lastEx = ex;
                    if (ex.Class >= 17 && ex.Class < 20)  // http://msdn.microsoft.com/en-us/library/ms164086.aspx
                    {
                        attempt--;
                        if (_AttemptDelay > 0 && attempt > 0)
                        {
                            try
                            {
                                Thread.Sleep(_AttemptDelay);
                            }
                            catch (Exception)
                            {
                                //Application Exception
                            }
                        }
                    }
                    else
                    {
                        if (ex.Class == 15) // SQL statement syntax error
                        {
                            Trace.WriteLine("[15] Bad SQL statement: " + cmd.CommandText);
                        }
                        else if (ex.Class == 14) // SQL permission error
                        {
                            Trace.WriteLine("[14] Missing SQL permissions for statement: " + cmd.CommandText);
                        }
                        else if (ex.Class == 11) // SQL object missing error
                        {
                            Trace.WriteLine("[11] Missing SQL object for statement: " + cmd.CommandText);
                        }
                        break;
                    }
                }
            }
            if (lastEx != null)
            {
                throw (lastEx);
            }
            throw (new Exception("Failed to make connection to the database."));
        }

        /// <summary>
        /// Runs the given command as a scalar query.
        /// </summary>
        /// <param name="cmd"></param>
        /// <returns></returns>
        public object Scalar(SqlCommand cmd)
        {
            if (string.IsNullOrEmpty(SafeConnectionString))
            {
                throw (new ArgumentNullException("SafeConnectionString", "Please set the connection string for the helper to use."));
            }
            int attempt = _MaxAttempts;
            SqlException lastEx = null;
            while (attempt > 0)
            {
                try
                {
                    using (SqlConnection con = new SqlConnection(SafeConnectionString))
                    {
                        con.Open();
                        cmd.Connection = con;
                        return (cmd.ExecuteScalar());
                    }
                }
                catch (SqlException ex)
                {
                    lastEx = ex;
                    if (ex.Class >= 17 && ex.Class < 20)  // http://msdn.microsoft.com/en-us/library/ms164086.aspx
                    {
                        attempt--;
                        if (_AttemptDelay > 0 && attempt > 0)
                        {
                            try
                            {
                                Thread.Sleep(_AttemptDelay);
                            }
                            catch (Exception)
                            {
                                //Application Exception
                            }
                        }
                    }
                    else
                    {
                        if (ex.Class == 15) // SQL statement syntax error
                        {
                            Trace.WriteLine("[15] Bad SQL statement: " + cmd.CommandText);
                        }
                        else if (ex.Class == 14) // SQL permission error
                        {
                            Trace.WriteLine("[14] Missing SQL permissions for statement: " + cmd.CommandText);
                        }
                        else if (ex.Class == 11) // SQL object missing error
                        {
                            Trace.WriteLine("[11] Missing SQL object for statement: " + cmd.CommandText);
                        }
                        break;
                    }
                }
            }
            if (lastEx != null)
            {
                throw (lastEx);
            }
            throw (new Exception("Failed to make connection to the database."));
        }

        /// <summary>
        /// Runs the given command as a scalar query.
        /// </summary>
        /// <param name="cmd"></param>
        /// <returns></returns>
        public SqlDataReader Reader(SqlCommand cmd)
        {
            if (string.IsNullOrEmpty(SafeConnectionString))
            {
                throw (new ArgumentNullException("SafeConnectionString", "Please set the connection string for the helper to use."));
            }
            int attempt = _MaxAttempts;
            SqlException lastEx = null;
            while (attempt > 0)
            {
                SqlConnection con = new SqlConnection(SafeConnectionString);
                try
                {
                    con.Open();
                    cmd.Connection = con;
                    return (cmd.ExecuteReader());
                }
                catch (SqlException ex)
                {
                    lastEx = ex;
                    if (ex.Class >= 17 && ex.Class < 20)  // http://msdn.microsoft.com/en-us/library/ms164086.aspx
                    {
                        attempt--;
                        if (_AttemptDelay > 0 && attempt > 0)
                        {
                            try
                            {
                                Thread.Sleep(_AttemptDelay);
                            }
                            catch (Exception)
                            {
                                //Application Exception
                            }
                        }
                    }
                    else if (ex.Class >= 20)
                    {
                        Trace.WriteLine("[" + ex.Class + "] Possible SQL database corruption. Please check the error logs on the SQL server immediately! Query: " + cmd.CommandText);
                        break;
                    }
                    else
                    {
                        if (ex.Class == 15) // SQL statement syntax error
                        {
                            Trace.WriteLine("[15] Bad SQL statement: " + cmd.CommandText);
                        }
                        else if (ex.Class == 14) // SQL permission error
                        {
                            Trace.WriteLine("[14] Missing SQL permissions for statement: " + cmd.CommandText);
                        }
                        else if (ex.Class == 11) // SQL object missing error
                        {
                            Trace.WriteLine("[11] Missing SQL object for statement: " + cmd.CommandText);
                        }
                        break;
                    }
                }
            }
            if (lastEx != null)
            {
                throw (lastEx);
            }
            throw (new Exception("Failed to make connection to the database."));
        }

        #endregion

    }
}
