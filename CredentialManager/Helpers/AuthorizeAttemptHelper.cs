using CredentialManager.DataEntities.CredentialStore;
using System;
using System.Linq;

namespace CredentialManager.Helpers
{
    public class AuthorizeAttemptHelper
    {
        /// <summary>
        /// reset user failed login attempts because of outdate locked time
        /// </summary>
        /// <param name="username"></param>
        public bool ResetLoginAttempts(string username)
        {
            bool userIsAllowedToLogin = true;

            if (!string.IsNullOrWhiteSpace(username))
            {
                using (CredentialManagerStoreEntities credStoreEntities = new CredentialManagerStoreEntities())
                {
                    var adUserContext = credStoreEntities.Principals.FirstOrDefault(p => p.UserName.ToLower().Equals(username.ToLower()));

                    if (adUserContext != null)
                    {
                        var loginAttempts = credStoreEntities.LoginAttempts.FirstOrDefault(l => l.PrincipalId == adUserContext.Id);
                        if (loginAttempts?.Locked == true)
                        {
                            if (DateTime.Now.AddMinutes(Constants.Constants.LockedMinutes) > loginAttempts.LockedTime)
                            {
                                credStoreEntities.LoginAttempts.Remove(loginAttempts);
                                credStoreEntities.SaveChanges();
                            }
                            else
                            {
                                userIsAllowedToLogin = false;
                            }
                        }
                    }
                }
            }

            return userIsAllowedToLogin;
        }

        /// <summary>
        /// removes user failed login attempts because of success authentication
        /// before maximum failed logins reached
        /// </summary>
        /// <param name="username"></param>
        public void RemoveLoginAttempts(string username)
        {
            using (CredentialManagerStoreEntities credStoreEntities = new CredentialManagerStoreEntities())
            {
                var adUserContext = credStoreEntities.Principals.FirstOrDefault(p => p.UserName.ToLower().Equals(username.ToLower()));
                if (adUserContext != null)
                {
                    var loginAttempts = credStoreEntities.LoginAttempts.FirstOrDefault(l => l.PrincipalId == adUserContext.Id);
                    if (loginAttempts != null)
                    {
                        credStoreEntities.LoginAttempts.Remove(loginAttempts);
                        credStoreEntities.SaveChanges();
                    }
                }

            }
        }
    }
}