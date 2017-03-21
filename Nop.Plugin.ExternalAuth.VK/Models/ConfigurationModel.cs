using Nop.Web.Framework;
using Nop.Web.Framework.Mvc;

namespace Nop.Plugin.ExternalAuth.VK.Models
{
    public class ConfigurationModel : BaseNopModel
    {
        public int ActiveStoreScopeConfiguration { get; set; }

        [NopResourceDisplayName("Plugins.ExternalAuth.VK.ClientKeyIdentifier")]
        public string ClientKeyIdentifier { get; set; }
        public bool ClientKeyIdentifier_OverrideForStore { get; set; }

        [NopResourceDisplayName("Plugins.ExternalAuth.VK.ClientSecret")]
        public string ClientSecret { get; set; }
        public bool ClientSecret_OverrideForStore { get; set; }
    }
}