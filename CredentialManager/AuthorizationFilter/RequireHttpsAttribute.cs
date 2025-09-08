using CredentialManager.Helpers;
using CredentialManager.Log;
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace CredentialManager.AuthorizationFilter
{
    /// <summary>
    /// class SSL RequireHttpsAttribute
    /// </summary>
    public class RequireHttpsAttribute : AuthorizationFilterAttribute
    {
        /// <summary>
        /// OnAuthorization SSL
        /// </summary>
        /// <param name="actionContext"></param>
        public override void OnAuthorization(HttpActionContext actionContext)
        {
            string requesterIp = ContextData.GetClientIpAddress(actionContext.Request);

            if (actionContext.Request.RequestUri.Scheme != Uri.UriSchemeHttps)
            {
                actionContext.Response = new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    ReasonPhrase = "HTTPS Required"
                };

                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}: ActionContext-Request has to be SSL", EventLogEntryType.Error);
            }
            else
            {
                X509Certificate2 cert = actionContext.Request.GetClientCertificate();

                if (cert != null)
                {
                    if (!cert.HasPrivateKey)
                    {
                        string issuer = cert.Issuer;
                        string subject = cert.Subject;
                        EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}: ClientCertificate delivered from Host/Ip: {ContextData.DetermineCompName(requesterIp).ToUpper()}, IsUser={issuer}, Subject={subject}, PublicKey={cert.PublicKey}", EventLogEntryType.Information);
                    }
                    else
                    {
                        actionContext.Response = new HttpResponseMessage(HttpStatusCode.Forbidden)
                        {
                            ReasonPhrase = "Clientcertificate has no PrivateKey"
                        };
                        EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}: ClientCertificate has no PrivateKey. Host: {ContextData.DetermineCompName(requesterIp).ToUpper()}", EventLogEntryType.Error);
                    }
                    
                }
                else
                {
                    actionContext.Response = new HttpResponseMessage(HttpStatusCode.Forbidden)
                    {
                        ReasonPhrase = "Clientcertificate is null"
                    };

                    EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}: Clientcertificate is null from Host: {ContextData.DetermineCompName(requesterIp).ToUpper()}", EventLogEntryType.Error);
                }

                base.OnAuthorization(actionContext);
            }
        }
    }
}