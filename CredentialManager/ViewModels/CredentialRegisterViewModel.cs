using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Web.Mvc;

namespace CredentialManager.ViewModels
{
    public class CredentialRegisterViewModel
    {
        /// <summary>
        /// Gets or sets the CredentialKey
        /// </summary>
        [Required]
        [Display(Name = "CredentialKey")]
        public string CredentialKey { get; set; }

        /// <summary>
        /// Gets or sets the CredentialType
        /// </summary>
        [Required]
        [Display(Name = "CredentialType")]
        public string CredentialType { get; set; }

        /// <summary>
        /// Gets or sets the UserName
        /// </summary>
        [Display(Name = "UserName")]
        public string UserName { get; set; }

        /// <summary>
        /// Gets or sets the Password
        /// </summary>
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        /// <summary>
        /// Gets or sets the ConfirmPassword
        /// </summary>
        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [System.ComponentModel.DataAnnotations.Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }

        /// <summary>
        /// Gets or sets the CredentialTypeList
        /// </summary>
        public List<SelectListItem> CredentialTypeList { get; set; }

        /// <summary>
        /// Gets or sets the UserRole
        /// </summary>
        public string UserRole { get; set; }

        /// <summary>
        /// Gets or sets the AuthenticationProtocol
        /// </summary>
        public string AuthenticationProtocol { get; set; }

        /// <summary>
        /// Gets or sets the AuthenticationProtocolList
        /// </summary>
        public List<SelectListItem> AuthenticationProtocolList { get; set; }

        /// <summary>
        /// Gets or sets the PrivacyProtocol
        /// </summary>
        public string PrivacyProtocol { get; set; }

        /// <summary>
        /// Gets or sets the PrivacyProtocolList
        /// </summary>
        public List<SelectListItem> PrivacyProtocolList { get; set; }

        /// <summary>
        /// Gets or sets the SSH private key
        /// </summary>
        [DataType(DataType.Password)]
        [Display(Name = "SSH Passphrase")]
        public string Sshpassphrase { get; set; }

        /// <summary>
        /// Gets or sets the SSH private key
        /// </summary>
        [Display(Name = "SSH Privatekey")]
        public string Sshprivatekey { get; set; }
    }
}