using CredentialManager.DataEntities.CredentialStore;
using CredentialManager.Log;
using CredentialManager.Models;
using CredentialManager.ViewModels;
using Microsoft.AspNet.Identity;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Reflection;
using System.Web.Mvc;

namespace CredentialManager.Controllers
{
    [RequireHttps]
    public class HomeController : Controller
    {
        /// <summary>
        /// main route
        /// </summary>
        /// <returns></returns>
        public ActionResult Index(ManageController.ManageMessageId? message)
        {
            ViewBag.StatusMessage =
                message == ManageController.ManageMessageId.CredentialExistInStore ? "Credential already exist in store."
                : "";

            CredentialRegisterViewModel model = new CredentialRegisterViewModel();
            CredentialRegisterModel credRegister = new CredentialRegisterModel();
            
            model.CredentialTypeList = credRegister.AddCredentialTypesToModel(model);
            model.AuthenticationProtocolList = credRegister.AddAuthenticationProtocolToModel(model);
            model.PrivacyProtocolList = credRegister.AddPrivacyProtocolToModel(model);

            return View(model);
        }

        /// <summary>
        /// add store credentials 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [Authorize()]
        [ValidateAntiForgeryToken]
        public ActionResult RegisterCredential(CredentialRegisterViewModel model)
        {

            CredentialRegisterModel credRegister = new CredentialRegisterModel();
            //insert new credential to store
            var message = credRegister.ValidateCredentialParams(model);
            if (message != null)
            {
                AddErrors(message);
            }

            if (!ModelState.IsValid)
            {
                model.CredentialTypeList = credRegister.AddCredentialTypesToModel(model);
                model.AuthenticationProtocolList = credRegister.AddAuthenticationProtocolToModel(model);
                model.PrivacyProtocolList = credRegister.AddPrivacyProtocolToModel(model);
                return View("Index", model);
            }

            
            IdentityResult result = credRegister.AddNewCredential(model, User);

            model = new CredentialRegisterViewModel();
            
            //assign credentialtypes/protocols to model
            model.CredentialTypeList = credRegister.AddCredentialTypesToModel(model);
            model.AuthenticationProtocolList = credRegister.AddAuthenticationProtocolToModel(model);
            model.PrivacyProtocolList = credRegister.AddPrivacyProtocolToModel(model);

            AddErrors(result);
            
            return View("Index", model);
        }

        /// <summary>
        /// Get credential store users
        /// </summary>
        /// <returns></returns>
        [Authorize]
        public ActionResult ManageCredential(ManageController.ManageMessageId? message)
        {
            ViewBag.StatusMessage =
                message == ManageController.ManageMessageId.ChangePasswordSuccess ? "Your password has been changed."
                : message == ManageController.ManageMessageId.SetPasswordSuccess ? "Your password has been set."
                : message == ManageController.ManageMessageId.RemoveLoginSuccess ? "The selected login was removed."
                : message == ManageController.ManageMessageId.RemoveCredentialSuccess ? "The selected credential was removed."
                : message == ManageController.ManageMessageId.Error ? "An error has occurred."
                : "";

            CredentialModel model = new CredentialModel();

            List<CredentialViewModel> credentialModel = model.LoadCredentials(User);

            return View(credentialModel);
        }

        /// <summary>
        /// principal init load
        /// </summary>
        /// <returns></returns>
        [Authorize(Roles = "Administrator")]
        public ActionResult ManagePrincipals()
        {
            PrincipalViewModel model = new PrincipalViewModel();
            PrincipalModel principalModel = new PrincipalModel();
            CredentialRoleModel credRoleModel = new CredentialRoleModel();

            model.CredentialRoles = credRoleModel.GetCredentialRoles();
            model.Principals = principalModel.GetPrincipals();
            return View(model);
        }

        /// <summary>
        /// Register new principal AD User
        /// </summary>
        /// <param name="adUser"></param>
        /// <param name="credRole"></param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator")]
        [ValidateAntiForgeryToken]
        public JsonResult RegisterPrincipals(string adUser, string credRole)
        {
            string message = string.Empty;
            bool result = false;

            if (!string.IsNullOrWhiteSpace(adUser) && !string.IsNullOrWhiteSpace(credRole))
            {
                using (CredentialManagerStoreEntities credEntties = new CredentialManagerStoreEntities())
                {
                    var principal = credEntties.Principals.FirstOrDefault(p => p.UserName.ToLower().Equals(adUser.ToLower()));
                    Guid.TryParse(credRole, out Guid roleGuid);
                    string usedDomain = ConfigurationManager.AppSettings["usedDomain"];

                    //validate aduser
                    using (var context = new PrincipalContext(ContextType.Domain, usedDomain))
                    {
                        using (var adUserFound = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, adUser))
                        {
                            if (adUserFound == null)
                            {
                                message = $"AdUser={adUser} is not a valid Active Directory account";
                            }
                            else
                            {
                                if (principal == null)
                                {
                                    try
                                    {
                                        Principals principals = new Principals();
                                        principals.Id = Guid.NewGuid();
                                        principals.UserName = adUser;
                                        principals.RoleId = roleGuid;
                                        principals.Active = true;
                                        principals.CreateTime = DateTime.Now;
                                        credEntties.Principals.Add(principals);
                                        credEntties.SaveChanges();
                                        result = true;
                                    }
                                    catch (Exception ex)
                                    {
                                        message = $"Error saving AdUser={adUser}. {ex.Message}";
                                    }
                                }
                                else
                                {
                                    message = $"AdUser={adUser} already assigned to CredentialManager";
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                message = "Please set AdUser and Role";
            }

            var validateUidResult = new { AddAdUserResult = result, Message = message };
            return Json(validateUidResult);
        }

        /// <summary>
        /// Validate AD User
        /// </summary>
        /// <param name="adUser"></param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator")]
        [ValidateAntiForgeryToken]
        public JsonResult ValidateAdUser(string adUser)
        {
            PrincipalModel principalModel = new PrincipalModel();
            string message = string.Empty;
            bool result = false;

            if (!string.IsNullOrWhiteSpace(adUser))
            {
                using (CredentialManagerStoreEntities credEntities = new CredentialManagerStoreEntities())
                {
                    var principals = credEntities.Principals.FirstOrDefault(p => p.UserName.ToLower().Equals(adUser.ToLower()));
                    
                    if (principals == null)
                    {
                        using (var context = new PrincipalContext(ContextType.Domain, "AUSTRIA"))
                        {
                            using (var adUserFound = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, adUser))
                            {
                                if (adUserFound != null)
                                {
                                    try
                                    {
                                        DirectoryEntry de = adUserFound.GetUnderlyingObject() as DirectoryEntry;
                                        principalModel.SamAccountName = $"{de.Properties["samAccountName"].Value}";
                                        principalModel.FirstName = $"{de.Properties["givenName"].Value}";
                                        principalModel.LastName = $"{de.Properties["sn"].Value}";

                                        //many details
                                        result = true;
                                    }
                                    catch (Exception ex)
                                    {
                                        message = $"AdUser {adUser} found with error: {ex.Message}";
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        message = $"AdUser {adUser} is already permitted";
                    }
                }
            }
            
            var validateUidResult = new { ValidateUIDResult = result, PrincipalModel = principalModel, Message = message };
            return Json(validateUidResult);
        }
        
        /// <summary>
        /// add errors to model
        /// </summary>
        /// <param name="result"></param>
        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        /// <summary>
        /// Get credential type name
        /// </summary>
        /// <param name="typeId"></param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator, CredentialWriter")]
        [ValidateAntiForgeryToken]
        public JsonResult GetCredentialTypeName(string typeId)
        {
            var sResult = String.Empty;

            try
            {
                Guid.TryParse(typeId, out Guid credentTypeId);


                using (CredentialManagerStoreEntities credStoreEntities = new CredentialManagerStoreEntities())
                {
                    var credType = credStoreEntities.CredentialTypes.FirstOrDefault(c => c.Id == credentTypeId);

                    if (credType != null)
                    {
                        sResult = JsonConvert.SerializeObject(credType.CredentialType);
                    }
                }
            }
            catch (Exception ex)
            {
                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. Error. {ex.Message}", EventLogEntryType.Error);
            }
            
            var jsonResult = new { CredentialTypeName = sResult };
            return Json(jsonResult);
        }
    }
}