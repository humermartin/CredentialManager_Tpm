using CredentialManager.Cryptography;
using CredentialManager.DataEntities.CredentialStore;
using CredentialManager.Log;
using Microsoft.AspNet.Identity;
using System;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Security.Principal;

namespace CredentialManager.Models
{
    public class ManageModel
    {
        /// <summary>
        /// remove store credential
        /// </summary>
        /// <param name="storeId"></param>
        /// <param name="adUser"></param>
        /// <returns></returns>
        public IdentityResult RemoveCredential(Guid storeId, IPrincipal adUser)
        {
            if (storeId != Guid.Empty)
            {
                using (CredentialManagerStoreEntities credStoreEntities = new CredentialManagerStoreEntities())
                {
                    IQueryable<UserCredentials> userCredentials = credStoreEntities.UserCredentials.Where(u => u.StoreId == storeId);

                    if (userCredentials.Any())
                    {
                        credStoreEntities.UserCredentials.RemoveRange(userCredentials);
                    }

                    var userStore = credStoreEntities.CredentialStore.FirstOrDefault(i => i.Id == storeId);

                    if (userStore != null)
                    {
                        credStoreEntities.CredentialStore.Remove(userStore);
                        credStoreEntities.SaveChanges();

                        //reload credentials into memory
                        VirtualTpmConfig.ProvideCredentials();

                        return IdentityResult.Success;
                    }
                }
            }
            return IdentityResult.Failed();
        }

        /// <summary>
        /// update store password
        /// </summary>
        /// <param name="storeId"></param>
        /// <param name="currentPassword"></param>
        /// <param name="newPassword"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        public IdentityResult ChangeStorePassword(Guid storeId, string currentPassword, string newPassword, IPrincipal user)
        {
            using (CredentialManagerStoreEntities credStoreEntities = new CredentialManagerStoreEntities())
            {
                var credUser = credStoreEntities.CredentialStore.FirstOrDefault(i => i.Id == storeId);
                
                if (credUser != null)
                {
                    TpmCryptography tpmCrypto = new TpmCryptography();
                    var storePwd = VirtualTpmConfig.CredentialEntities.FirstOrDefault(i => i.Id == storeId)?.Password;
                    if (currentPassword != SecureStringParams.SecureStringToString(storePwd))
                    {
                        return IdentityResult.Failed("current password is wrong");
                    }

                    if (currentPassword == newPassword)
                    {
                        return IdentityResult.Failed("new password does not differ from current password");
                    }

                    credUser.Password = tpmCrypto.EncryptKey(newPassword);
                    credUser.LastChange = DateTime.Now;

                    credStoreEntities.SaveChanges();

                    //reload credentials into memory
                    VirtualTpmConfig.ProvideCredentials();

                    EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name} User = {user.Identity.Name} has changed Credentialpassword for CredentialKey: {tpmCrypto.DecryptKey(credUser.CredentialKey)}, CredentialType: {credUser.CredentialType}", EventLogEntryType.Information);
                    return IdentityResult.Success;
                    
                }
                
                return IdentityResult.Failed("user not found");
            }
        }
    }
}