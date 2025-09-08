using CredentialManager.Cryptography;
using CredentialManager.DataEntities.CredentialStore;
using CredentialManager.Models;
using CredentialManager.Log;
using log4net;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;

namespace CredentialManager
{
    public static class VirtualTpmConfig
    {
        /// <summary>
        /// Member which holds the log4net logger
        /// </summary>
        private static readonly ILog Log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        /// <summary>
        /// Member which holds the credential list in memory
        /// </summary>
        public static List<CredentialEntity> CredentialEntities;

        /// <summary>
        /// provide credentials by loading vTPM decryption into memory
        /// </summary>
        public static void ProvideCredentials()
        {
            try
            {
                Log.Info($"{MethodBase.GetCurrentMethod().Name}. Start providing credentials.");

                using (CredentialManagerStoreEntities credStoreEntities = new CredentialManagerStoreEntities())
                {
                    List<CredentialStore> credStoreList = credStoreEntities.CredentialStore.ToList();

                    TpmCryptography tpmCrypto = new TpmCryptography();

                    CredentialEntities?.Clear();
                    CredentialEntities = new List<CredentialEntity>();

                    Log.Info(credStoreList.Any()
                        ? $"{MethodBase.GetCurrentMethod().Name}. Load vTPM decryption into memory."
                        : $"{MethodBase.GetCurrentMethod().Name}. Store is empty. vTPM decryption not possible.");

                    foreach (var credential in credStoreList)
                    {
                        CredentialEntity credModel = new CredentialEntity();

                        credModel.Id = credential.Id;
                        
                        if (!string.IsNullOrWhiteSpace(credential.CredentialKey))
                        {
                            credModel.CredentialKey = SecureStringParams.CreateSecureString(tpmCrypto.DecryptKey(credential.CredentialKey));
                        }

                        if (!string.IsNullOrWhiteSpace(credential.CredentialType))
                        {
                            credModel.CredentialType = SecureStringParams.CreateSecureString(credential.CredentialType);
                        }

                        if (!string.IsNullOrWhiteSpace(credential.UserName))
                        {
                            credModel.UserName = SecureStringParams.CreateSecureString(tpmCrypto.DecryptKey(credential.UserName));
                        }

                        if (!string.IsNullOrWhiteSpace(credential.Password))
                        {
                            credModel.Password = SecureStringParams.CreateSecureString(tpmCrypto.DecryptKey(credential.Password));
                        }

                        if (!string.IsNullOrWhiteSpace(credential.AuthenticationProtocol))
                        {
                            credModel.AuthenticationProtocol = SecureStringParams.CreateSecureString(tpmCrypto.DecryptKey(credential.AuthenticationProtocol));
                        }

                        if (!string.IsNullOrWhiteSpace(credential.PrivacyProtocol))
                        {
                            credModel.PrivacyProtocol = SecureStringParams.CreateSecureString(tpmCrypto.DecryptKey(credential.PrivacyProtocol));
                        }

                        if (!string.IsNullOrWhiteSpace(credential.SSHphassphrase))
                        {
                            credModel.SshPassphrase = SecureStringParams.CreateSecureString(tpmCrypto.DecryptKey(credential.SSHphassphrase));
                        }

                        if (!string.IsNullOrWhiteSpace(credential.SSHprivatekey))
                        {
                            credModel.SshPrivatekey = SecureStringParams.CreateSecureString(credential.SSHprivatekey);
                        }

                        CredentialEntities.Add(credModel);
                    }
                }
            }
            catch (Exception ex)
            {
                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. Error. {ex.Message}", EventLogEntryType.Error);
            }
            
        }
    }
}
