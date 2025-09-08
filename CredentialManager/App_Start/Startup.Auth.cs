using System;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;

namespace CredentialManager
{
    public partial class Startup
    {
        public static class MyAuthentication
        {
            public const string ApplicationCookie = "CredManCookie";
        }


        // For more information on configuring authentication, please visit https://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // need to add UserManager into owin, because this is used in cookie invalidation
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = MyAuthentication.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider(),
                CookieName = "adCookie",
                CookieSecure = CookieSecureOption.Always,
                ExpireTimeSpan = TimeSpan.FromMinutes(30), // adjust to your needs
            });
        }
    }
}