using Nop.Core.Plugins;
using Nop.Services.Authentication.External;
using Nop.Services.Configuration;
using Nop.Services.Localization;
using System.Web.Routing;

namespace Nop.Plugin.ExternalAuth.VK
{
    public class VKExternalAuthMethod : BasePlugin, IExternalAuthenticationMethod
    {
        private readonly ISettingService _settingService;

        public VKExternalAuthMethod(ISettingService settingService)
        {
            this._settingService = settingService;
        }

        public void GetConfigurationRoute(out string actionName, out string controllerName, out RouteValueDictionary routeValues)
        {
            actionName = "Configure";
            controllerName = "ExternalAuthVK";
            routeValues = new RouteValueDictionary() { { "Namespaces", "Nop.Plugin.ExternalAuth.VK.Controllers" }, { "area", null } };

        }

        public void GetPublicInfoRoute(out string actionName, out string controllerName, out RouteValueDictionary routeValues)
        {
            actionName = "PublicInfo";
            controllerName = "ExternalAuthVK";
            routeValues = new RouteValueDictionary() { { "Namespaces", "Nop.Plugin.ExternalAuth.VK.Controllers" }, { "area", null } };

        }

        public override void Install()
        {
            //settings
            var settings = new VKExternalAuthSettings()
            {
                ClientKeyIdentifier = "",
                ClientSecret = "",
            };
            _settingService.SaveSetting(settings);

            //locales

            this.AddOrUpdatePluginLocaleResource("Plugins.ExternalAuth.VK.ClientKeyIdentifier", "Client ID");
            this.AddOrUpdatePluginLocaleResource("Plugins.ExternalAuth.VK.ClientKeyIdentifier.Hint", "Enter your Client ID key here. You can find it on VK Developers console page.");
            this.AddOrUpdatePluginLocaleResource("Plugins.ExternalAuth.VK.ClientSecret", "Client Secret");
            this.AddOrUpdatePluginLocaleResource("Plugins.ExternalAuth.VK.ClientSecret.Hint", "Enter your client secret here. You can find it on your VK Developers console page.");

            base.Install();
        }

        public override void Uninstall()
        {
            //settings
            _settingService.DeleteSetting<VKExternalAuthSettings>();

            //locales
            this.DeletePluginLocaleResource("Plugins.ExternalAuth.VK.ClientKeyIdentifier");
            this.DeletePluginLocaleResource("Plugins.ExternalAuth.VK.ClientKeyIdentifier.Hint");
            this.DeletePluginLocaleResource("Plugins.ExternalAuth.VK.ClientSecret");
            this.DeletePluginLocaleResource("Plugins.ExternalAuth.VK.ClientSecret.Hint");

            base.Uninstall();
        }

    }
}
