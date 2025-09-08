using System;
using System.Security;

namespace CredentialManager.Models
{
    public class CredentialEntity
    {
        /// <summary>
        /// Gets or sets the Store Id
        /// </summary>
        public Guid Id { get; set; }

        /// <summary>
        /// Gets or sets the CredentialKey
        /// </summary>
        public SecureString CredentialKey { get; set; }

        /// <summary>
        /// Gets or sets the CredentialType
        /// </summary>
        public SecureString CredentialType { get; set; }

        /// <summary>
        /// Gets or sets the UserName
        /// </summary>
        public SecureString UserName { get; set; }

        /// <summary>
        /// Gets or sets the Password
        /// </summary>
        public SecureString Password { get; set; }

        /// <summary>
        /// Gets or sets the SSH passphrase
        /// </summary>
        public SecureString SshPassphrase { get; set; }

        /// <summary>
        /// Gets or sets the SSH private key
        /// </summary>
        public SecureString SshPrivatekey { get; set; }

        /// <summary>
        /// Gets or sets the Authentication Protocol
        /// </summary>
        public SecureString AuthenticationProtocol { get; set; }

        /// <summary>
        /// Gets or sets the Privacy Protocol
        /// </summary>
        public SecureString PrivacyProtocol { get; set; }
        
    }
}