using CredentialManager.DataEntities.CredentialStore;
using System;
using System.Collections.Generic;

namespace CredentialManager.Models
{
    public class AdUserModel
    {
        /// <summary>
        /// Gets or sets the Username
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// Gets or sets the Fullname
        /// </summary>
        public string FullName { get; set; }

        /// <summary>
        /// Gets or sets the Role
        /// </summary>
        public CredentialRole CredentialRole { get; set; }

        /// <summary>
        /// Gets or sets the active/inactive value
        /// </summary>
        public bool Active { get; set; }

        /// <summary>
        /// Gets or sets the created time
        /// </summary>
        public DateTime CreatedTime { get; set; }

        /// <summary>
        /// Gets or sets the aduser Id
        /// </summary>
        public Guid Id { get; set; }

        /// <summary>
        /// Gets or sets the assigned store id
        /// </summary>
        public bool IsAssignedToStoreId { get; set; }

        /// <summary>
        /// Gets or sets the store collection
        /// </summary>
        public List<CredentialStore> CredentialStore { get; set; }

        /// <summary>
        /// Gets or sets the assigned count
        /// </summary>
        public int CredentialsAssignedCount { get; set; }

        /// <summary>
        /// Gets or sets the html title
        /// </summary>
        public string Title { get; set; }
    }
}