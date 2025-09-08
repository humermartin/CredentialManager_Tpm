namespace CredentialManager.Models
{
    public class CredentialResponseModel
    {
        /// <summary>
        /// Gets or sets the UserName
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// Gets or sets the Password
        /// </summary>
        public string Password { get; set; }

        /// <summary>
        /// Gets or sets the SSH passphrase
        /// </summary>
        public string SshPassphrase { get; set; }

        /// <summary>
        /// Gets or sets the SSH private key
        /// </summary>
        public string SshPrivatekey { get; set; }

        /// <summary>
        /// Gets or sets the Authentication Protocol
        /// </summary>
        public string AuthenticationProtocol { get; set; }

        /// <summary>
        /// Gets or sets the Privacy Protocol
        /// </summary>
        public string PrivacyProtocol { get; set; }

    }
}