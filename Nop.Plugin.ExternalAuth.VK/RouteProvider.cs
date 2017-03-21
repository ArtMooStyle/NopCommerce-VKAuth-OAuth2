using Nop.Web.Framework.Mvc.Routes;
using System.Web.Mvc;
using System.Web.Routing;

namespace Nop.Plugin.ExternalAuth.VK
{
    public partial class RouteProvider : IRouteProvider
    {
        public void RegisterRoutes(RouteCollection routes)
        {
            routes.MapRoute("Plugin.ExternalAuth.VK.Login",
                 "Plugins/ExternalAuthVK/Login",
                 new { controller = "ExternalAuthVK", action = "Login" },
                 new[] { "Nop.Plugin.ExternalAuth.VK.Controllers" }
            );

            routes.MapRoute("Plugin.ExternalAuth.VK.LoginCallback",
                 "Plugins/ExternalAuthVK/LoginCallback",
                 new { controller = "ExternalAuthVK", action = "LoginCallback" },
                 new[] { "Nop.Plugin.ExternalAuth.VK.Controllers" }
            );
        }
        public int Priority
        {
            get
            {
                return 0;
            }
        }
    }
}
