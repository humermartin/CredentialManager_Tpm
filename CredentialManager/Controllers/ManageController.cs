using CredentialManager.Cryptography;
using CredentialManager.DataEntities.CredentialStore;
using CredentialManager.Models;
using CredentialManager.Log;
using CredentialManager.ViewModels;
using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace CredentialManager.Controllers
{
    [RequireHttps]
    [Authorize]
    public class ManageController : Controller
    {
        /// <summary>
        /// GET: /Manage/ChangeCredentialPassword
        /// </summary>
        /// <returns></returns>
        [Authorize(Roles = "Administrator, CredentialWriter")]
        public ActionResult ChangeCredentialPassword(Guid id)
        {
            ChangePasswordViewModel model = new ChangePasswordViewModel();
            model.Id = id;

            var store = VirtualTpmConfig.CredentialEntities.FirstOrDefault(c => c.Id == model.Id);
            if (store != null && !string.IsNullOrWhiteSpace(SecureStringParams.SecureStringToString(store.UserName)))
            {
                model.UserName = SecureStringParams.SecureStringToString(store.UserName);
            }
            
            return View(model);
        }

        /// <summary>
        /// POST: /Manage/ChangePassword
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Administrator, CredentialWriter")]
        public ActionResult ChangeCredentialPassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            ManageModel manageModel = new ManageModel();
            var result = manageModel.ChangeStorePassword(model.Id, model.OldPassword, model.NewPassword, User);
            if (result.Succeeded)
            {
                return RedirectToAction("ManageCredential", "Home", new { Message = ManageMessageId.ChangePasswordSuccess });
            }

            AddErrors(result);
            return View(model);
        }

        /// <summary>
        /// remove credential store login
        /// </summary>
        /// <param name="storeId"></param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator, CredentialWriter")]
        [ValidateAntiForgeryToken]
        public JsonResult RemoveCredential(string storeId)
        {
            string message = string.Empty;
            bool jsonResult = false;

            if (!string.IsNullOrWhiteSpace(storeId))
            {
                Guid.TryParse(storeId, out Guid storeGuid);

                ManageModel model = new ManageModel();

                IdentityResult result = model.RemoveCredential(storeGuid, User);

                if (result.Succeeded)
                {
                    message = "Credential successfully removed.";
                    EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. User={User.Identity.Name} removed credential. {message}", EventLogEntryType.Information);
                    jsonResult = true;
                }
                else
                {
                    message = "Failed to remove Credential.";
                    EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. User={User.Identity.Name} tried to remove credential. Status failed.", EventLogEntryType.Error);
                }
            }

            var validateResult = new { RemoveCredentialResult = jsonResult, Message = message };
            return Json(validateResult);
        }

        /// <summary>
        /// remove credential store login
        /// </summary>
        /// <param name="serviceCallStatus"></param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator, CredentialWriter")]
        [ValidateAntiForgeryToken]
        public JsonResult SetCredStoreServiceCall(bool serviceCallStatus)
        {
            CredentialStoreController.ServiceEnabled = serviceCallStatus;
            var validateResult = new { Message = $"Service Call status set to {serviceCallStatus}" };
            return Json(validateResult);
        }

        /// <summary>
        /// Remove AdUser and his roles and not assigned credentials
        /// </summary>
        /// <param name="principalId"></param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator")]
        [ValidateAntiForgeryToken]
        public JsonResult RemoveAdUserAccount(string principalId)
        {
            string message = string.Empty;
            string redirectUrl = string.Empty;
            bool result = false;
            
            if (!string.IsNullOrWhiteSpace(principalId))
            {
                try
                {
                    Guid.TryParse(principalId, out Guid principalGuid);

                    using (CredentialManagerStoreEntities credStoreEntities = new CredentialManagerStoreEntities())
                    {
                        var principal = credStoreEntities.Principals.FirstOrDefault(p => p.Id == principalGuid);
                        if (principal != null)
                        {
                            string adUserName = principal.UserName;

                            //Step 1: get storeIds from user and check if any storeIds are assigned to other users
                            List<Guid> adUserStoreIds = credStoreEntities.UserCredentials.Where(u => u.UserId == principal.Id).Select(s => s.StoreId).ToList();

                            //Step 2: search for assigned storeIds 
                            List<Guid> assignedStoreIds = credStoreEntities.UserCredentials.Where(a => adUserStoreIds.Contains(a.StoreId) && a.UserId != principal.Id).Select(s => s.StoreId).ToList();

                            //Step 3: filter not assigned StoreIds where we can remove from store
                            List<Guid> filteredStoreIdsToRemove = adUserStoreIds.Except(assignedStoreIds).ToList();

                            //Step 4: remove storeIds from adUser
                            if (filteredStoreIdsToRemove.Any())
                            {
                                var credStoreEntriesToRemove = credStoreEntities.CredentialStore.Where(c => filteredStoreIdsToRemove.Contains(c.Id));
                                if (credStoreEntriesToRemove.Any())
                                {
                                    credStoreEntities.CredentialStore.RemoveRange(credStoreEntriesToRemove);
                                }
                            }
                            
                            //Step 5: remove aduser from usercredentials
                            var adUserCredentials = credStoreEntities.UserCredentials.Where(u => u.UserId == principalGuid);
                            if (adUserCredentials.Any())
                            {
                                credStoreEntities.UserCredentials.RemoveRange(adUserCredentials);
                            }

                            //Step 6: remove ad user principal
                            credStoreEntities.Principals.Remove(principal);

                            //Step 7: commit
                            credStoreEntities.SaveChanges();

                            //Step 8: if loggedInUser removes his own account. log off
                            if (adUserName.ToLower().Equals(User.Identity.Name.ToLower()))
                            {
                                //sign out
                                if (Request.Cookies["adCookie"] != null)
                                {
                                    var c = new HttpCookie("adCookie");
                                    c.Expires = DateTime.Now.AddDays(-1);
                                    Response.Cookies.Add(c);
                                    FormsAuthentication.SignOut();
                                }
                                redirectUrl = Url.Action("Login", "Account");
                            }
                            else
                            {
                                redirectUrl = Url.Action("ManagePrincipals", "Home");
                            }
                            
                            message = $"AdUser {adUserName} successfull removed. All credentials except other user assigned credentials are removed.";
                            EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. User={User.Identity.Name} removed AdUser. {message}", EventLogEntryType.Information);
                            result = true;
                        }
                        else
                        {
                            message = "Remove AdUser not possible. User not found.";
                            EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. User={User.Identity.Name} tried to removed AdUser. {message}", EventLogEntryType.Information);
                        }
                    }
                }
                catch (Exception ex)
                {
                    message = ex.Message;
                    EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. Error: {message}", EventLogEntryType.Error);
                }
                
            }

            var validateResult = new { RemoveAdUserResult = result, Message = message, RedirectUrl = redirectUrl };
            return Json(validateResult);
        }

        /// <summary>
        /// update adUser activation status
        /// </summary>
        /// <param name="principalId"></param>
        /// <param name="active"></param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator")]
        [ValidateAntiForgeryToken]
        public JsonResult UpdateAdUserActivation(string principalId, bool active)
        {
            string message = string.Empty;
            bool result = false;

            try
            {
                if (!string.IsNullOrWhiteSpace(principalId))
                {
                    using (CredentialManagerStoreEntities credStoreEntities = new CredentialManagerStoreEntities())
                    {
                        Guid.TryParse(principalId, out Guid principalGuid);

                        var principal = credStoreEntities.Principals.FirstOrDefault(p => p.Id == principalGuid);

                        if (principal != null)
                        {
                            principal.Active = active;
                            credStoreEntities.SaveChanges();
                            message = active ? $"Aduser {principal.UserName} is now active." : $"Aduser {principal.UserName} is now deactivated.";
                            EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. User={User.Identity.Name} changed User State. {message}", EventLogEntryType.Information);
                            result = true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                message = ex.Message;
                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. Error: {message}", EventLogEntryType.Error);
            }
            
            var validateResult = new { UpdateActivationResult = result, Message = message };
            return Json(validateResult);

        }


        /// <summary>
        /// update adUser activation status
        /// </summary>
        /// <param name="principalId"></param>
        /// <param name="roleId"></param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator")]
        [ValidateAntiForgeryToken]
        public JsonResult UpdateAdUserRole(string principalId, string roleId)
        {

            string message = string.Empty;
            bool result = false;

            if (!string.IsNullOrWhiteSpace(principalId) && !string.IsNullOrWhiteSpace(roleId))
            {
                Guid.TryParse(principalId, out Guid principalGuid);
                Guid.TryParse(roleId, out Guid roleGuid);

                using (CredentialManagerStoreEntities credStoreEntities = new CredentialManagerStoreEntities())
                {
                    var principal = credStoreEntities.Principals.FirstOrDefault(p => p.Id == principalGuid);

                    if (principal != null)
                    {
                        var previousRole = principal.CredentialRole.RoleName;
                        principal.RoleId = roleGuid;
                        credStoreEntities.SaveChanges();

                        var newRole = credStoreEntities.CredentialRole.FirstOrDefault(r => r.Id == roleGuid);
                        message = $"Role changed for AdUser {principal.UserName} from {previousRole} to {newRole?.RoleName}.";
                        EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. User={User.Identity.Name} changed UserRole. {message}", EventLogEntryType.Information);
                        result = true;
                    }
                    else
                    {
                        message = "Cannot change Role. AdUser not found.";
                        EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. {message}", EventLogEntryType.Information);
                    }
                }
                
            }
            var validateResult = new { UpdateAdUserRoleResult = result, Message = message };
            return Json(validateResult);
        }

        /// <summary>
        /// update credential user assignment
        /// add/remove credential2user assignment
        /// </summary>
        /// <param name="storeId"></param>
        /// <param name="userId"></param>
        /// <param name="checkValue"></param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator")]
        [ValidateAntiForgeryToken]
        public JsonResult UpdateCredentialAssignement(string storeId, string userId, bool checkValue)
        {
            string message = string.Empty;
            bool result = false;

            try
            {
                if (!string.IsNullOrWhiteSpace(storeId) && !string.IsNullOrWhiteSpace(userId))
                {
                    Guid.TryParse(storeId, out Guid storeGuid);
                    Guid.TryParse(userId, out Guid adUserGuid);

                    using (CredentialManagerStoreEntities credStoreEntities = new CredentialManagerStoreEntities())
                    {
                        var userCredentialExist = credStoreEntities.UserCredentials.FirstOrDefault(u => u.StoreId == storeGuid && u.UserId == adUserGuid);
                        var userName = credStoreEntities.Principals.FirstOrDefault(f => f.Id == adUserGuid)?.UserName;

                        if (checkValue == true)
                        {
                            //add UserCredential
                            if (userCredentialExist == null)
                            {
                                UserCredentials userCredentials = new UserCredentials();
                                userCredentials.Id = Guid.NewGuid();
                                userCredentials.StoreId = storeGuid;
                                userCredentials.UserId = adUserGuid;
                                userCredentials.CreateTime = DateTime.Now;
                                credStoreEntities.UserCredentials.Add(userCredentials);
                                credStoreEntities.SaveChanges();
                                message = "User credential assignment done.";
                                var store = credStoreEntities.CredentialStore.FirstOrDefault(s => s.Id == storeGuid);
                                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name} - Added User-Assignement. User = {userName} added to Store for Type = {store?.CredentialType}", EventLogEntryType.Information);
                            }
                        }
                        else
                        {
                            //remove UserCredential
                            if (userCredentialExist != null)
                            {
                                var tmpCredStore = userCredentialExist.CredentialStore;
                                credStoreEntities.UserCredentials.Remove(userCredentialExist);
                                credStoreEntities.SaveChanges();
                                message = "User credential removed.";
                                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name} - Removed User-Assignement. User = {userName} removed from Store for Type = {tmpCredStore.CredentialType}", EventLogEntryType.Information);
                            }
                        }
                        
                        result = true;
                    }
                }
            }
            catch (Exception ex)
            {
                message = $"Could not save credential assignement to users. Error: {ex.Message}";
                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. Error: {ex.Message}", EventLogEntryType.Error);
            }
            
            var validateResult = new { UpdateAdUserRoleResult = result, Message = message };
            return Json(validateResult);
        }

        /// <summary>
        /// Load active principals
        /// </summary>
        /// <param name="storeId"></param>
        /// <param name="skip"></param>
        /// <param name="take"></param>
        /// <param name="filter"></param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator, CredentialWriter")]
        [ValidateAntiForgeryToken]
        public JsonResult LoadPrincipals(string storeId, int skip, int take, string filter)
        {

            if (string.IsNullOrWhiteSpace(storeId)) return null;

            PrincipalViewModel model = new PrincipalViewModel();
            List<AdUserModel> adUsersList = new List<AdUserModel>();

            Guid.TryParse(storeId, out Guid storeGuid);

            using (CredentialManagerStoreEntities credStoreEntities = new CredentialManagerStoreEntities())
            {
                var principals = credStoreEntities.Principals.Where(p => p.Active && !p.UserName.ToLower().Equals(User.Identity.Name.ToLower())).ToList().OrderBy(o => o.UserName);

                foreach (var principal in principals)
                {
                    AdUserModel adUser = new AdUserModel();
                    adUser.Id = principal.Id;
                    adUser.UserName = principal.UserName.ToUpper();
                    adUser.CreatedTime = principal.CreateTime;

                    var userIsAssigned = credStoreEntities.UserCredentials.FirstOrDefault(f => f.StoreId == storeGuid && f.UserId == principal.Id);
                    if (userIsAssigned != null)
                    {
                        adUser.IsAssignedToStoreId = true;
                    }
                    adUsersList.Add(adUser);
                }

                model.ModelDescription = "User assignement: Add Users to Credential";
                model.Principals = adUsersList;
                model.PrincipalsTotalCount = adUsersList.Count;
            }
            
            return Json(model, JsonRequestBehavior.AllowGet);
        }

        /// <summary>
        /// add model error
        /// </summary>
        /// <param name="result"></param>
        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }
        
        public enum ManageMessageId
        {
            ChangePasswordSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
            Error,
            CredentialExistInStore,
            RemoveCredentialSuccess
        }
    }
}