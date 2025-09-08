using System.Collections.Generic;
using System.Configuration;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Text;
using CredentialManager.Cryptography;
using CredentialManager.DataEntities.CredentialStore;

namespace CredentialManager.Models
{
    public class PrincipalModel
    {
        /// <summary>
        /// Gets or sets the SamAccountName
        /// </summary>
        public string SamAccountName { get; set; }

        /// <summary>
        /// Gets or sets the FirstName
        /// </summary>
        public string FirstName { get; set; }

        /// <summary>
        /// Gets or sets the LastName
        /// </summary>
        public string LastName { get; set; }

        /// <summary>
        /// Gets the permitted adUser principals
        /// </summary>
        /// <returns></returns>
        public List<AdUserModel> GetPrincipals()
        {
            List<AdUserModel>adUserList = new List<AdUserModel>();

            using (CredentialManagerStoreEntities credStoreEntities = new CredentialManagerStoreEntities())
            {
                var principals = credStoreEntities.Principals.ToList().OrderBy(o => o.CredentialRole.RoleName);

                foreach (var principal in principals)
                {
                    AdUserModel adUserModel = new AdUserModel();
                    adUserModel.Id = principal.Id;
                    adUserModel.UserName = principal.UserName;
                    string usedDomain = ConfigurationManager.AppSettings["usedDomain"];

                    using (var context = new PrincipalContext(ContextType.Domain, usedDomain))
                    {
                        using (var adUserFound = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, adUserModel.UserName))
                        {
                            if (adUserFound != null)
                            {
                                adUserModel.FullName = $"{adUserFound.GivenName} {adUserFound.Surname}";
                            }
                        }
                    }

                    adUserModel.CredentialRole = principal.CredentialRole;

                    List<CredentialStore> assignedStore = credStoreEntities.UserCredentials.Where(c => c.UserId == principal.Id).Select(c => c.CredentialStore).ToList();
                    if (assignedStore.Any())
                    {
                        adUserModel.CredentialsAssignedCount = assignedStore.Count;

                        StringBuilder sb = new StringBuilder();
                        TpmCryptography tpmCrypto = new TpmCryptography();
                        foreach (var credential in assignedStore)
                        {
                            sb.AppendLine($"{tpmCrypto.DecryptKey(credential.CredentialKey) }/{credential.CredentialType}");
                        }

                        adUserModel.Title = sb.ToString();

                    }
                    
                    adUserModel.Active = principal.Active;
                    adUserModel.CreatedTime = principal.CreateTime;
                    adUserList.Add(adUserModel);
                }
            }

            return adUserList;
        }
    }
}