using System.Configuration;
using System.Web.Configuration;

namespace CredentialManager
{
    public static class WebConfig
    {
        public static void Register()
        {
            EncryptConnString();
        }

        /// <summary>
        /// Encrypt web.config sections
        /// </summary>
        private static void EncryptConnString()
        {

            Configuration config = WebConfigurationManager.OpenWebConfiguration("/");
            ConfigurationSection connSection = config.GetSection("connectionStrings");
            ConfigurationSection appSection = config.GetSection("appSettings");
            if (!connSection.SectionInformation.IsProtected)
            {
                connSection.SectionInformation.ProtectSection("RsaProtectedConfigurationProvider");
                config.Save();
            }
            if (!appSection.SectionInformation.IsProtected)
            {
                appSection.SectionInformation.ProtectSection("RsaProtectedConfigurationProvider");
                config.Save();
            }
        }
    }
}
