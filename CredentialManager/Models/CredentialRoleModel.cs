using CredentialManager.DataEntities.CredentialStore;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;

namespace CredentialManager.Models
{
    /// <summary>
    /// Gets the CredentialRoles as SelectListItem list
    /// </summary>
    public class CredentialRoleModel
    {
        /// <summary>
        /// Get CredentialRoles
        /// </summary>
        /// <returns></returns>
        public IEnumerable<SelectListItem> GetCredentialRoles()
        {
            List<SelectListItem> listItems = new List<SelectListItem>();

            using (CredentialManagerStoreEntities credentialStoreEntities = new CredentialManagerStoreEntities())
            {
                var credRoles = credentialStoreEntities.CredentialRole.ToList();

                foreach (var role in credRoles)
                {
                    listItems.Add(new SelectListItem
                    {
                        Value = role.Id.ToString(),
                        Text = role.RoleName
                    });
                }
            }

            return listItems;
        }
    }
}