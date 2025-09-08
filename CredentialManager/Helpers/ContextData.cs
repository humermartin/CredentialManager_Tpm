using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Web;
using CredentialManager.Log;

namespace CredentialManager.Helpers
{
    /// <summary>
    /// helper class registry
    /// </summary>
    public class ContextData
    {
        /// <summary>
        /// get registry key
        /// </summary>
        /// <returns></returns>
        /// <summary>
        /// get request ip address
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        public static string GetClientIpAddress(HttpRequestMessage request)
        {
            try
            {
                if (request.Properties.ContainsKey("MS_HttpContext"))
                {
                    return IPAddress.Parse(((HttpContextBase)request.Properties["MS_HttpContext"]).Request.UserHostAddress).ToString();
                }
                return String.Empty;
            }
            catch (Exception ex)
            {
                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. Error. {ex.Message}", EventLogEntryType.Error);
                return string.Empty;
            }
            
        }

        /// <summary>
        /// Gets the requester hostname
        /// </summary>
        /// <param name="ip"></param>
        /// <returns></returns>
        public static string DetermineCompName(string ip)
        {
            try
            {
                IPAddress myIp = IPAddress.Parse(ip);
                IPHostEntry getIpHost = Dns.GetHostEntry(myIp);
                List<string> compName = getIpHost.HostName.Split('.').ToList();
                return compName.First();
            }
            catch (Exception ex)
            {
                return ip;
            }
            
        }


    }
}