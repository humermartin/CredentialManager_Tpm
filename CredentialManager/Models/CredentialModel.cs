using CredentialManager.Cryptography;
using CredentialManager.DataEntities.CredentialStore;
using CredentialManager.ViewModels;
using System.Collections.Generic;
using System.Linq;

namespace CredentialManager.Models
{
    public class CredentialModel
    {
        /// <summary>
        /// load credentials
        /// </summary>
        /// <returns></returns>
        public List<CredentialViewModel> LoadCredentials(System.Security.Principal.IPrincipal user)
        {
            List<CredentialViewModel> credentialModelList = new List<CredentialViewModel>();
            using (CredentialManagerStoreEntities credStoreEntities = new CredentialManagerStoreEntities())
            {
                var currentPrincipal = credStoreEntities.Principals.FirstOrDefault(a => a.UserName.ToLower().Equals(user.Identity.Name.ToLower()));
                if (currentPrincipal == null) return null;
                
                var credStoreUsers = credStoreEntities.CredentialStore.Where(c => c.UserCredentials.Where(s => s.UserId == currentPrincipal.Id).Select(s => s.StoreId).Contains(c.Id));

                if (credStoreUsers.Any())
                {
                    TpmCryptography tpmCrypto = new TpmCryptography();

                    foreach (var storeUser in credStoreUsers)
                    {
                        CredentialViewModel model = new CredentialViewModel();
                        
                        model.Id = storeUser.Id;

                        model.CredentialKey = tpmCrypto.DecryptKey(storeUser.CredentialKey);
                        model.CredentialType = storeUser.CredentialType;

                        if (!string.IsNullOrWhiteSpace(storeUser.UserName))
                        {
                            model.UserName = tpmCrypto.DecryptKey(storeUser.UserName);
                        }
                        model.HasPassword = !string.IsNullOrEmpty(storeUser.Password);

                        model.LastChange = storeUser.LastChange;
                        model.CreateTime = storeUser.CreateTime;

                        credentialModelList.Add(model);
                    }

                    return credentialModelList;
                }
            }

            return null;
        }
    }
}