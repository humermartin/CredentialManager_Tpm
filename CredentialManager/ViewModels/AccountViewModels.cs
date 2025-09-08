using System.ComponentModel.DataAnnotations;

namespace CredentialManager.ViewModels
{
    public class LoginViewModel
    {
        /// <summary>
        /// Gets or sets the Login UserName
        /// </summary>
        [Required]
        [Display(Name = "UserName")]
        public string UserName { get; set; }

        /// <summary>
        /// Gets or sets the Login Password
        /// </summary>
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

    }
}
