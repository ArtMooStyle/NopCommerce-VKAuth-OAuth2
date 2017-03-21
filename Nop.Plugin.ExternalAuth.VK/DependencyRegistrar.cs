using Autofac;
using Nop.Core.Infrastructure;
using Nop.Core.Configuration;
using Nop.Core.Infrastructure.DependencyManagement;
using Nop.Plugin.ExternalAuth.VK.Core;

namespace Nop.Plugin.ExternalAuth.VK
{
    public class DependencyRegistrar : IDependencyRegistrar
    {
        public virtual void Register
            (ContainerBuilder builder, 
            ITypeFinder typeFinder, 
            NopConfig config)
        {
            builder.RegisterType<VKProviderAuthorizer>()
                .As<IOAuthProviderVKAuthorizer>().InstancePerLifetimeScope();
        }

        public int Order
        {
            get { return 1; }
        }
    }
}
