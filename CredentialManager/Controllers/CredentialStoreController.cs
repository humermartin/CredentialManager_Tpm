using CredentialManager.AuthorizationFilter;
using CredentialManager.Cryptography;
using CredentialManager.Helpers;
using CredentialManager.Log;
using CredentialManager.Models;
using log4net;
using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Reflection;
using System.Web.Http;

namespace CredentialManager.Controllers
{
    [RequireHttps]
    [WebApiAuthenticationFilter]
    [RoutePrefix("api/CredentialStore")]
    public class CredentialStoreController : ApiController
    {
        /// <summary>
        /// Member which holds the log4net logger
        /// </summary>
        private static readonly ILog Log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        /// <summary>
        /// Gets or sets the ServiceEnabled flag
        /// </summary>
        public static bool ServiceEnabled { get; set; } = true;

        /// <summary>
        /// get store credential by credential key and type
        /// </summary>
        /// <param name="credKey"></param>
        /// <param name="credType"></param>
        /// <returns></returns>
        [Route("GetCredential/{credKey}/{credType}")]
        public HttpResponseMessage GetCredential(string credKey, string credType)
        {
            try
            {
                if (!ServiceEnabled)
                {
                    HttpResponseMessage methodNotEnabled = Request.CreateResponse(HttpStatusCode.MethodNotAllowed, "Service currently not available.", JsonMediaTypeFormatter.DefaultMediaType);
                    Log.Warn($"{MethodBase.GetCurrentMethod().Name}. WebService GetCredential is currently not available.");
                    return methodNotEnabled;
                }

                var credModel = GetCredentialByKey(credKey, credType);
                HttpResponseMessage response = Request.CreateResponse(HttpStatusCode.OK, credModel, JsonMediaTypeFormatter.DefaultMediaType);
                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. WebService call GetCredential from Host: {ContextData.DetermineCompName(ContextData.GetClientIpAddress(ActionContext.Request)).ToUpper()} for Key/Type: {credKey}/{credType}", EventLogEntryType.Information);
                return response;
            }
            catch (Exception ex)
            {
                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. Error. {ex.Message}", EventLogEntryType.Error);
                HttpResponseMessage errResponse = Request.CreateResponse(HttpStatusCode.InternalServerError, ex.Message, JsonMediaTypeFormatter.DefaultMediaType);
                return errResponse;
            }
            
        }

        /// <summary>
        /// Gets the credential by delivered key
        /// </summary>
        /// <param name="credKey"></param>
        /// <param name="credType"></param>
        /// <returns></returns>
        protected CredentialResponseModel GetCredentialByKey(string credKey, string credType)
        {
            CredentialResponseModel credModel = new CredentialResponseModel();

            try
            {
                if (!string.IsNullOrEmpty(credKey))
                {

                    var credentialEntities = VirtualTpmConfig.CredentialEntities;

                    if (!credentialEntities.Any() || credentialEntities == null)
                    {
                        Log.Warn($"{MethodBase.GetCurrentMethod().Name}. No credentials loaded into memory.");
                        return credModel;
                    }

                    var credStoreDict = credentialEntities.ToList().ToDictionary(a => a. CredentialKey, b => b.CredentialType);

                    foreach (var credStore in credStoreDict)
                    {
                        var credStoreKey = SecureStringParams.SecureStringToString(credStore.Key);
                        var credStoreValue = SecureStringParams.SecureStringToString(credStore.Value);

                        if (credKey == credStoreKey && credType == credStoreValue)
                        {
                            var credMatch = credentialEntities.FirstOrDefault(c => SecureStringParams.SecureStringToString(c.CredentialKey) == credStoreKey && SecureStringParams.SecureStringToString(c.CredentialType) == credStoreValue);
                            if (credMatch != null)
                            {
                                
                                if (!string.IsNullOrWhiteSpace(SecureStringParams.SecureStringToString(credMatch.UserName)))
                                {
                                    credModel.UserName = SecureStringParams.SecureStringToString(credMatch.UserName);
                                }

                                if (!string.IsNullOrWhiteSpace(SecureStringParams.SecureStringToString(credMatch.Password)))
                                {
                                    credModel.Password = SecureStringParams.SecureStringToString(credMatch.Password);
                                }

                                if (!string.IsNullOrWhiteSpace(SecureStringParams.SecureStringToString(credMatch.AuthenticationProtocol)))
                                {
                                    credModel.AuthenticationProtocol = SecureStringParams.SecureStringToString(credMatch.AuthenticationProtocol);
                                }

                                if (!string.IsNullOrWhiteSpace(SecureStringParams.SecureStringToString(credMatch.PrivacyProtocol)))
                                {
                                    credModel.PrivacyProtocol = SecureStringParams.SecureStringToString(credMatch.PrivacyProtocol);
                                }

                                if (!string.IsNullOrWhiteSpace(SecureStringParams.SecureStringToString(credMatch.SshPassphrase)))
                                {
                                    credModel.SshPassphrase = SecureStringParams.SecureStringToString(credMatch.SshPassphrase);
                                }

                                if (!string.IsNullOrWhiteSpace(SecureStringParams.SecureStringToString(credMatch.SshPrivatekey)))
                                {
                                    credModel.SshPrivatekey = SecureStringParams.SecureStringToString(credMatch.SshPrivatekey);
                                }

                                //Log.Info($"UserName:{credModel.UserName}, Password:{credModel.Password}, AuthenticationProtocol:{credModel.AuthenticationProtocol}, PrivacyProtocol:{credModel.PrivacyProtocol}, SshPassphrase:{credModel.SshPassphrase}, SshPrivatekey:{credModel.SshPrivatekey} ");
                                
                                break;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. Error. {ex.Message}", EventLogEntryType.Error);
                return credModel;
            }

            return credModel;
        }
    }
}
