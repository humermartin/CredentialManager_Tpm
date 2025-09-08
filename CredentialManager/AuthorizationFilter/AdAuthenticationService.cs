using CredentialManager.DataEntities.CredentialStore;
using CredentialManager.Helpers;
using CredentialManager.Log;
using Microsoft.Owin.Security;
using System;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Reflection;
using System.Security.Claims;

namespace CredentialManager.AuthorizationFilter
{
    public class AdAuthenticationService
    {
        /// <summary>
        /// Sets the authentication manaager
        /// </summary>
        private readonly IAuthenticationManager authenticationManager;

        public AdAuthenticationService(IAuthenticationManager authenticationManager)
        {
            this.authenticationManager = authenticationManager;
        }
        
        /// <summary>
        /// Check if username and password matches existing account in AD. 
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public AuthenticationResult SignIn(string username, string password)
        {
            // authenticates against your Domain AD
            ContextType authenticationType = ContextType.Domain;
            AuthorizeAttemptHelper attemptHelper = new AuthorizeAttemptHelper();

            PrincipalContext principalContext = new PrincipalContext(authenticationType);
            bool isAuthenticated = false;
            UserPrincipal userPrincipal = null;
            try
            {
                userPrincipal = UserPrincipal.FindByIdentity(principalContext, username);
                if (userPrincipal != null)
                {
                    //validate login attempt reseting
                    bool loginAllowed = attemptHelper.ResetLoginAttempts(username);

                    if (loginAllowed)
                    {
                        isAuthenticated = principalContext.ValidateCredentials(username, password, ContextOptions.Negotiate);
                    }
                    else
                    {
                        return new AuthenticationResult("User is locked.");
                    }
                    

                    if (isAuthenticated)
                    {
                        //remove loginAttempts
                        attemptHelper.RemoveLoginAttempts(username);
                    }
                }
            }
            catch (Exception)
            {
                return new AuthenticationResult("Username or Password is not correct");
            }

            using (CredentialManagerStoreEntities credStoreEntities = new CredentialManagerStoreEntities())
            {
                var adUserContext = credStoreEntities.Principals.FirstOrDefault(p => p.UserName.ToLower().Equals(username.ToLower()));

                if (userPrincipal == null)
                {
                    return new AuthenticationResult("Username or Password is not correct");
                }

                if (userPrincipal.IsAccountLockedOut())
                {
                    // here can be a security related discussion wether it is worth 
                    // revealing this information. User is locked in Active Directory
                    return new AuthenticationResult("Your account is locked.");
                }

                if (userPrincipal.Enabled.HasValue && userPrincipal.Enabled.Value == false)
                {
                    // here can be a security related discussion weather it is worth 
                    // revealing this information
                    return new AuthenticationResult("Your account is disabled");
                }

                if (adUserContext != null && adUserContext.Active == false)
                {
                    return new AuthenticationResult("Your account is deactived.");
                }

                if (adUserContext == null)
                {
                    return new AuthenticationResult("Your account is not permitted.");
                }

                //login failed
                if (!isAuthenticated)
                {
                    var loginAttempts = credStoreEntities.LoginAttempts.FirstOrDefault(l => l.PrincipalId == adUserContext.Id);

                    if (loginAttempts != null)
                    {
                        if (loginAttempts.Locked != null && loginAttempts.Locked == true)
                        {
                            return new AuthenticationResult("Your account is locked.");
                        }

                        if (loginAttempts.Attempts > 0 && loginAttempts.Attempts < Constants.Constants.MaximumLoginAttempts)
                        {
                            if (loginAttempts.Attempts + 1 == Constants.Constants.MaximumLoginAttempts)
                            {
                                loginAttempts.Attempts = Constants.Constants.MaximumLoginAttempts;
                                loginAttempts.Locked = true;
                                loginAttempts.LockedTime = DateTime.Now;
                                credStoreEntities.SaveChanges();

                                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. User={username} failed to login {Constants.Constants.MaximumLoginAttempts} times. User is locked now.", EventLogEntryType.Information);
                                
                                return new AuthenticationResult("Your account is locked");
                            }
                            else
                            {
                                loginAttempts.Attempts = loginAttempts.Attempts + 1;
                                credStoreEntities.SaveChanges();

                                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. User={username} failed to login {loginAttempts.Attempts} time(s).", EventLogEntryType.Information);
                                
                                return new AuthenticationResult($"Username or Password is not correct. You have {Constants.Constants.MaximumLoginAttempts - loginAttempts.Attempts} more attempts.");
                            }
                            
                        }
                    }
                    else
                    {
                        LoginAttempts newLoginAttempts = new LoginAttempts();
                        newLoginAttempts.Id = Guid.NewGuid();
                        newLoginAttempts.Attempts = 1;
                        newLoginAttempts.Locked = false;
                        newLoginAttempts.PrincipalId = adUserContext.Id;
                        credStoreEntities.LoginAttempts.Add(newLoginAttempts);
                        credStoreEntities.SaveChanges();

                        EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. User={username} failed to login first time.", EventLogEntryType.Information);

                        return new AuthenticationResult($"Username or Password is not correct. You have {Constants.Constants.MaximumLoginAttempts - 1} more attempts.");
                    }
                }
            }

            var identity = CreateIdentity(userPrincipal);

            authenticationManager.SignOut(Startup.MyAuthentication.ApplicationCookie);
            authenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = false }, identity);


            return new AuthenticationResult();
        }

        /// <summary>
        /// creates and add claim identities
        /// </summary>
        /// <param name="userPrincipal"></param>
        /// <returns></returns>
        private ClaimsIdentity CreateIdentity(UserPrincipal userPrincipal)
        {
            var identity = new ClaimsIdentity(Startup.MyAuthentication.ApplicationCookie, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
            identity.AddClaim(new Claim("http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider", "Active Directory"));
            identity.AddClaim(new Claim(ClaimTypes.Name, userPrincipal.SamAccountName));
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userPrincipal.SamAccountName));
            identity.AddClaim(new Claim(ClaimTypes.GivenName, userPrincipal.GivenName));

            using (CredentialManagerStoreEntities credEntities = new CredentialManagerStoreEntities())
            {
                string userPrincipalRole = string.Empty;
                Principals principal = credEntities.Principals.FirstOrDefault(p => p.UserName.ToLower().Equals(userPrincipal.SamAccountName.ToLower()));
                if (principal != null)
                {
                    CredentialRole userRole = credEntities.CredentialRole.FirstOrDefault(r => r.Id == principal.RoleId);
                    if (userRole != null)
                    {
                        userPrincipalRole = userRole.RoleName;
                    }
                }
                identity.AddClaim(new Claim(ClaimTypes.Role, userPrincipalRole));
            }
            

            if (!string.IsNullOrWhiteSpace(userPrincipal.EmailAddress))
            {
                identity.AddClaim(new Claim(ClaimTypes.Email, userPrincipal.EmailAddress));
            }

            return identity;
        }
    }
}