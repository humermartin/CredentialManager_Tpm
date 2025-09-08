using System;

namespace CredentialManager.ViewModels
{
    public class CredentialViewModel
    {
        /// <summary>
        /// Gets or sets the Id
        /// </summary>
        public Guid Id { get; set; }

        /// <summary>
        /// Gets or sets the CredentialKey
        /// </summary>
        public string CredentialKey { get; set; }

        /// <summary>
        /// Gets or sets the CredentialType
        /// </summary>
        public string CredentialType { get; set; }

        /// <summary>
        /// Gets or sets the UserName
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// Gets or sets the Password
        /// </summary>
        public string Password { get; set; }

        /// <summary>
        /// Gets or sets the HasPassword
        /// </summary>
        public bool HasPassword { get; set; }

        /// <summary>
        /// Gets or sets the Created Time
        /// </summary>
        public DateTime? CreateTime { get; set; }

        /// <summary>
        /// Gets or sets the LastChange Time
        /// </summary>
        public DateTime? LastChange { get; set; }
        
    }
}