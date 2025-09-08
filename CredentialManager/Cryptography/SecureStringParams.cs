using log4net;
using System;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;

namespace CredentialManager.Cryptography
{
    public class SecureStringParams
    {

        /// <summary>
        /// Member which holds the log4net logger
        /// </summary>
        private static readonly ILog Log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        /// <summary>
        /// secure confidential memory values
        /// </summary>
        /// <param name="toSecure"></param>
        /// <returns></returns>
        public static SecureString CreateSecureString(string toSecure)
        {
            try
            {
                SecureString sec = new SecureString();

                Array.ForEach(toSecure.ToArray(), sec.AppendChar);
                sec.MakeReadOnly();
                return sec;
            }
            catch (Exception ex)
            {
                Log.Error($"{MethodBase.GetCurrentMethod().Name}: Error: {ex.Message}");
                return null;
            }
            
        }

        /// <summary>
        /// reconvert confidential values
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string SecureStringToString(SecureString value)
        {
            try
            {
                if (value != null)
                {
                    IntPtr valuePtr = IntPtr.Zero;
                    try
                    {
                        valuePtr = Marshal.SecureStringToGlobalAllocUnicode(value);
                        return Marshal.PtrToStringUni(valuePtr);
                    }
                    finally
                    {
                        Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
                    }
                }
                return null;
            }
            catch (Exception ex)
            {
                Log.Error($"{MethodBase.GetCurrentMethod().Name}: Error: {ex.Message}");
                return null;
            }
        }

    }
}