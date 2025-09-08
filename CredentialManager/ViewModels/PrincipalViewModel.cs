using CredentialManager.Models;
using System.Collections.Generic;
using System.Web.Mvc;

namespace CredentialManager.ViewModels
{
    public class PrincipalViewModel
    {
        /// <summary>
        /// Gets or sets the Modeldescription
        /// </summary>
        public string ModelDescription { get; set; }

        /// <summary>
        /// Gets or sets the CredentRoles
        /// </summary>
        public IEnumerable<SelectListItem> CredentialRoles { get; set; }

        /// <summary>
        /// Gets or sets the CredentialRole
        /// </summary>
        public string CredentialRole { get; set; }

        /// <summary>
        /// Gets or sets the Principal collection
        /// </summary>
        public List<AdUserModel> Principals { get; set; }

        /// <summary>
        /// Gets or sets the Principal total count
        /// </summary>
        public int PrincipalsTotalCount { get; set; }
    }
}