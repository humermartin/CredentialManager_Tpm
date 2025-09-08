using CredentialManager.DataEntities.CredentialStore;
using CredentialManager.Helpers;
using CredentialManager.Log;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Web.Http.Controllers;

namespace CredentialManager.AuthorizationFilter
{
    /// <summary>
    /// Custom basic authentication class
    /// </summary>
    public class WebApiAuthenticationFilter : BasicAuthenticationFilter
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public WebApiAuthenticationFilter()
        { }

        /// <summary>
        /// Overload constructor
        /// </summary>
        /// <param name="active"></param>
        public WebApiAuthenticationFilter(bool active) : base(active)
        { }


        /// <summary>
        /// Basic authentication
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="actionContext"></param>
        /// <returns></returns>
        protected override bool OnAuthorizeUser(string username, string password, HttpActionContext actionContext)
        {
            string requesterIp = ContextData.GetClientIpAddress(actionContext.Request);

            using (CredentialManagerStoreEntities credManEntities = new CredentialManagerStoreEntities())
            {
                var credReader = credManEntities.ServiceUsers.FirstOrDefault(f => f.UserName == username);

                if (credReader != null)
                {
                    VerifyIdentities verifyIdentities = new VerifyIdentities();
                    var verified = verifyIdentities.VerifyHashedPassword(username, credReader.PasswordHash, password);

                    bool authenticated = verified;

                    EventLogger.WriteToLog(
                        authenticated
                            ? $"{MethodBase.GetCurrentMethod().Name}: REST service call. User is authorized. Host/Ip: {ContextData.DetermineCompName(requesterIp).ToUpper()}, IpAdress: {requesterIp}"
                            : $"{MethodBase.GetCurrentMethod().Name}: Not authorized. User is not permitted. Host/Ip: {ContextData.DetermineCompName(requesterIp).ToUpper()}, IpAdress: {requesterIp}",
                        EventLogEntryType.Information);
                    
                    return authenticated;
                }
                
                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}: Not authorized. User is not permitted. Host/Ip: {ContextData.DetermineCompName(requesterIp).ToUpper()}, IpAdress: {requesterIp}", EventLogEntryType.Information);

                return false;
            }
        }
    }
}