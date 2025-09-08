using CredentialManager.Log;
using System;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;

namespace CredentialManager
{
    /// <summary>
    /// Verify hash password
    /// </summary>
    public class VerifyIdentities
    {
        public bool VerifyHashedPassword(string username, string hashedPassword, string password)
        {
            byte[] buffer4;
            if (hashedPassword == null)
            {
                return false;
            }
            if (password == null)
            {
                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}: Not authorized. User {username} is not permitted. No given password", EventLogEntryType.Information);
                return false;
            }
            byte[] src = Convert.FromBase64String(hashedPassword);
            if ((src.Length != 0x31) || (src[0] != 0))
            {
                return false;
            }
            byte[] dst = new byte[0x10];
            Buffer.BlockCopy(src, 1, dst, 0, 0x10);
            byte[] buffer3 = new byte[0x20];
            Buffer.BlockCopy(src, 0x11, buffer3, 0, 0x20);
            using (Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(password, dst, 0x3e8))
            {
                buffer4 = bytes.GetBytes(0x20);
            }
            return ByteArraysEqual(buffer3, buffer4);
        }

        /// <summary>Compares two byte arrays for equality.</summary>
        /// <param name="b0">First byte array.</param><param name="b1">Second byte array.</param>
        /// <returns>true if the arrays are equal; false otherwise.</returns>
        private bool ByteArraysEqual(byte[] b0, byte[] b1)
        {
            if (b0 == b1)
            {
                return true;
            }

            if (b0 == null || b1 == null)
            {
                return false;
            }

            if (b0.Length != b1.Length)
            {
                return false;
            }

            for (int i = 0; i < b0.Length; i++)
            {
                if (b0[i] != b1[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
