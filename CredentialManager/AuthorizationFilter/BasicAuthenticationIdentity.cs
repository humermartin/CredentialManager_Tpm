using System.Security.Principal;

namespace CredentialManager.AuthorizationFilter
{
    public class BasicAuthenticationIdentity : GenericIdentity
    {
        /// <summary>
        /// Gets or sets the Password
        /// </summary>
        public string Password { get; set; }

        /// <summary>
        /// constructor
        /// </summary>
        /// <param name="name"></param>
        /// <param name="password"></param>
        public BasicAuthenticationIdentity(string name, string password): base(name, "Basic")
        {
            this.Password = password;
        }  
    }
}