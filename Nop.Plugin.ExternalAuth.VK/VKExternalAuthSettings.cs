using Nop.Core.Configuration;

namespace Nop.Plugin.ExternalAuth.VK
{
    public class VKExternalAuthSettings : ISettings
    {
        public string ClientKeyIdentifier { get; set; }
        public string ClientSecret { get; set; }
    }
}
