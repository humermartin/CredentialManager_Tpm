using CredentialManager.AuthorizationFilter;
using CredentialManager.Log;
using CredentialManager.ViewModels;
using Microsoft.Owin.Security;
using System.Diagnostics;
using System.Reflection;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;


namespace CredentialManager.Controllers
{
    [System.Web.Mvc.RequireHttps]
    [Authorize]
    public class AccountController : Controller
    {
        /// <summary>
        /// Gets the authentication manager
        /// </summary>
        private IAuthenticationManager AuthenticationManager => HttpContext.GetOwinContext().Authentication;

        /// <summary>
        /// GET: /Account/Login 
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        /// <summary>
        /// POST: /Account/Login 
        /// </summary>
        /// <param name="model"></param>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            IAuthenticationManager authenticationManager = HttpContext.GetOwinContext().Authentication;
            var authService = new AdAuthenticationService(authenticationManager);

            var authenticationResult = authService.SignIn(model.UserName, model.Password);

            if (authenticationResult.IsSuccess)
            {
                // we are in!
                EventLogger.WriteToLog($"{MethodBase.GetCurrentMethod().Name}. User = {model.UserName} logged in.", EventLogEntryType.Information);
                return RedirectToLocal(returnUrl);
            }
            
            ModelState.AddModelError("", authenticationResult.ErrorMessage);
            return View(model);

        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut(Startup.MyAuthentication.ApplicationCookie);
            
            return RedirectToAction("Index", "Home");
        }

        /// <summary>
        /// redirects to local
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }
    }
}