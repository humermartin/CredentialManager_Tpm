using CredentialManager.Cryptography;
using CredentialManager.DataEntities.CredentialStore;
using CredentialManager.Log;
using CredentialManager.ViewModels;
using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Data.Entity.Validation;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Web.Mvc;
using log4net;

namespace CredentialManager.Models
{
    public class CredentialRegisterModel
    {

        /// <summary>
        /// log4net setter
        /// </summary>
        protected static readonly ILog Log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        /// <summary>
        /// add new credential to store
        /// </summary>
        /// <param name="model"></param>
        /// <param name="adUser"></param>
        /// <returns></returns>
        public IdentityResult AddNewCredential(CredentialRegisterViewModel model, IPrincipal adUser)
        {
            try
            {
                using (CredentialManagerStoreEntities credentialStoreEntities = new CredentialManagerStoreEntities())
                {
                    Guid selCredType = new Guid(model.CredentialType);
                    var credType = credentialStoreEntities.CredentialTypes.FirstOrDefault(c => c.Id == selCredType);
                    
                    if (credType != null)
                    {
                        TpmCryptography tpmCrypto = new TpmCryptography();
                        
                        //validate unique key/type combination
                        Dictionary<Guid, CredentialStore> credPairExiStore = credentialStoreEntities.CredentialStore.ToDictionary(x => x.Id, x => x);

                        foreach (var credPair in credPairExiStore)
                        {
                            CredentialStore credPairObject = credPair.Value;
                            string dictKey = tpmCrypto.DecryptKey(credPairObject.CredentialKey);
                            string dictType = credPairObject.CredentialType;

                            if (model.CredentialKey.Equals(dictKey) && credType.CredentialType.Equals(dictType))
                            {
                                //not unique key/type combination
                                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}: Cannot insert new credential for user {model.UserName}. User already exist with same credentialKey and credentialType.", EventLogEntryType.Information);
                                return IdentityResult.Failed($"Cannot insert new credential for user {model.UserName}. User already exist with same credentialKey and credentialType.");
                            }
                        }

                        //insert new key/type credential
                        CredentialStore crdStore = new CredentialStore();
                        crdStore.Id = Guid.NewGuid();
                        crdStore.CredentialKey = tpmCrypto.EncryptKey(model.CredentialKey);
                        crdStore.CredentialType = credType.CredentialType;

                        //UserName
                        if (!string.IsNullOrWhiteSpace(model.UserName))
                        {
                            crdStore.UserName = tpmCrypto.EncryptKey(model.UserName);
                        }

                        //Password
                        if (!string.IsNullOrWhiteSpace(model.Password))
                        {
                            crdStore.Password = tpmCrypto.EncryptKey(model.Password);
                        }

                        //AuthenticationProtocol
                        if (!string.IsNullOrWhiteSpace(model.AuthenticationProtocol))
                        {
                            Guid.TryParse(model.AuthenticationProtocol, out Guid authProtocolId);
                            var authProt = credentialStoreEntities.AuthenticationProtocol.FirstOrDefault(a => a.Id == authProtocolId);
                            if (authProt != null)
                            {
                                crdStore.AuthenticationProtocol = tpmCrypto.EncryptKey(authProt.AuthenticationProtocol1);
                            }
                            
                        }

                        //PrivacyProtocol
                        if (!string.IsNullOrWhiteSpace(model.PrivacyProtocol))
                        {
                            Guid.TryParse(model.PrivacyProtocol, out Guid privacyProtocolId);
                            var privacyProt = credentialStoreEntities.PrivacyProtocol.FirstOrDefault(a => a.Id == privacyProtocolId);
                            if (privacyProt != null)
                            {
                                crdStore.PrivacyProtocol = tpmCrypto.EncryptKey(privacyProt.PrivacyProtocol1);
                            }
                        }

                        //SSHphassphrase
                        if (!string.IsNullOrWhiteSpace(model.Sshpassphrase))
                        {
                            crdStore.SSHphassphrase = tpmCrypto.EncryptKey(model.Sshpassphrase);
                        }

                        //SSHprivatekey
                        if (!string.IsNullOrWhiteSpace(model.Sshprivatekey))
                        {
                            //crdStore.SSHprivatekey = tpmCrypto.EncryptKey(model.Sshprivatekey); => currently not possible size too large
                            crdStore.SSHprivatekey = model.Sshprivatekey;
                        }

                        crdStore.SecurityStamp = Guid.NewGuid().ToString();
                        crdStore.CreateTime = DateTime.Now;
                        crdStore.LastChange = DateTime.Now;
                        credentialStoreEntities.CredentialStore.Add(crdStore);
                        credentialStoreEntities.SaveChanges();

                        
                        Principals userFound = credentialStoreEntities.Principals.FirstOrDefault(p => p.UserName.ToLower().Equals(adUser.Identity.Name.ToLower()));
                        if (userFound != null)
                        {
                            //add credentialStore to UserCredentials
                            UserCredentials userCredentials = new UserCredentials();
                            userCredentials.Id = Guid.NewGuid();
                            userCredentials.StoreId = crdStore.Id;
                            userCredentials.UserId = userFound.Id;
                            userCredentials.CreateTime = DateTime.Now;
                            credentialStoreEntities.UserCredentials.Add(userCredentials);
                            credentialStoreEntities.SaveChanges();
                        }
                        else
                        {
                            return IdentityResult.Failed($"Could not assign credential to user {adUser.Identity.Name}.");
                        }

                        //reload credentials into memory
                        VirtualTpmConfig.ProvideCredentials();

                        return IdentityResult.Success;
                    }

                    return IdentityResult.Failed("Could not found Passphrase or CredentialType");
                }
            }
            catch (DbEntityValidationException e)
            {
                foreach (var eve in e.EntityValidationErrors)
                {
                    Log.Error($"Entity of type {eve.Entry.Entity.GetType().Name} in state {eve.Entry.State} has the following validation errors:");
                    foreach (var ve in eve.ValidationErrors)
                    {
                        Log.Error($"- Property: { ve.PropertyName}, Error: {ve.ErrorMessage}");
                    }
                }
                return IdentityResult.Failed("DbEntityValidationException: See logfile for more infos.");
            }
            catch (Exception ex)
            {
                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}: Error: {ex.Message}.", EventLogEntryType.Information);
                return IdentityResult.Failed(ex.Message);
            }
        }

        /// <summary>
        /// get credentialtypes from store
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        public List<SelectListItem> AddCredentialTypesToModel(CredentialRegisterViewModel model)
        {
            //reload CredentialTypes
            List<SelectListItem> listItems = new List<SelectListItem>();

            using (CredentialManagerStoreEntities credentialStoreEntities = new CredentialManagerStoreEntities())
            {
                var credentialTypes = credentialStoreEntities.CredentialTypes.ToList();

                foreach (var credType in credentialTypes)
                {
                    listItems.Add(new SelectListItem
                    {
                        Text = credType.CredentialType,
                        Value = credType.Id.ToString()
                    });
                }
            }
            listItems.Insert(0, new SelectListItem() { Text = "", Value = "" });
            return listItems;
        }

        public List<SelectListItem> AddAuthenticationProtocolToModel(CredentialRegisterViewModel model)
        {
            //reload AuthenticationProtocol
            List<SelectListItem> listItems = new List<SelectListItem>();

            using (CredentialManagerStoreEntities credentialStoreEntities = new CredentialManagerStoreEntities())
            {
                var authenticationProtocols = credentialStoreEntities.AuthenticationProtocol.ToList();

                foreach (var authProtocol in authenticationProtocols)
                {
                    listItems.Add(new SelectListItem
                    {
                        Text = authProtocol.AuthenticationProtocol1,
                        Value = authProtocol.Id.ToString()
                    });
                }
            }
            listItems.Insert(0, new SelectListItem() { Text = "", Value = "" });
            return listItems;
        }

        public List<SelectListItem> AddPrivacyProtocolToModel(CredentialRegisterViewModel model)
        {
            //reload PrivacyProtocol
            List<SelectListItem> listItems = new List<SelectListItem>();

            using (CredentialManagerStoreEntities credentialStoreEntities = new CredentialManagerStoreEntities())
            {
                var privacyProtocols = credentialStoreEntities.PrivacyProtocol.ToList();

                foreach (var privacyProtocol in privacyProtocols)
                {
                    listItems.Add(new SelectListItem
                    {
                        Text = privacyProtocol.PrivacyProtocol1,
                        Value = privacyProtocol.Id.ToString()
                    });
                }
            }
            listItems.Insert(0, new SelectListItem() { Text = "", Value = "" });
            return listItems;
        }

        /// <summary>
        /// Validate credentials depends on CredentialType
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        public IdentityResult ValidateCredentialParams(CredentialRegisterViewModel model)
        {
            using (CredentialManagerStoreEntities credentialManagerStoreEntities = new CredentialManagerStoreEntities())
            {
                Guid.TryParse(model.CredentialType, out Guid credTypeId);
                var credStore = credentialManagerStoreEntities.CredentialTypes.FirstOrDefault(c => c.Id == credTypeId);

                if (credStore != null)
                {
                    switch (credStore.CredentialType)
                    {
                        case "cim":
                        case "ssh_password":
                        case "mssql":
                        case "vmware":
                        case "windows":
                            if (string.IsNullOrWhiteSpace(model.UserName))
                            {
                                return IdentityResult.Failed("UserName is required");
                            }else if (string.IsNullOrWhiteSpace(model.Password))
                            {
                                return IdentityResult.Failed("Password is required");
                            }
                            break;
                        case "snmp":
                            if (string.IsNullOrWhiteSpace(model.Password))
                            {
                                return IdentityResult.Failed("UserName is required");
                            }
                            break;
                        case "snmpv3":
                            if (string.IsNullOrWhiteSpace(model.UserName))
                            {
                                return IdentityResult.Failed("UserName is required");
                            }
                            else if (string.IsNullOrWhiteSpace(model.AuthenticationProtocol))
                            {
                                return IdentityResult.Failed("AuthenticationProtocol is required");
                            }
                            else if (string.IsNullOrWhiteSpace(model.PrivacyProtocol))
                            {
                                return IdentityResult.Failed("PrivacyProtocol is required");
                            }
                            break;
                        case "ssh_private_key":
                            if (string.IsNullOrWhiteSpace(model.UserName))
                            {
                                return IdentityResult.Failed("UserName is required");
                            }
                            else if (string.IsNullOrWhiteSpace(model.Sshpassphrase))
                            {
                                return IdentityResult.Failed("SSH passphrase is required");
                            }
                            else if (string.IsNullOrWhiteSpace(model.Sshprivatekey))
                            {
                                return IdentityResult.Failed("SSH private key is required");
                            }
                            break;
                    }
                }
            }
            

            return null;
        }
    }
}
