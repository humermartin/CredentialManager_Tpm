using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(CredentialManager.Startup))]
namespace CredentialManager
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
