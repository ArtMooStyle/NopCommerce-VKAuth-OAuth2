using Nop.Core;
using Nop.Core.Domain.Customers;
using Nop.Core.Plugins;
using Nop.Plugin.ExternalAuth.VK.Core;
using Nop.Plugin.ExternalAuth.VK.Models;
using Nop.Services.Authentication.External;
using Nop.Services.Configuration;
using Nop.Services.Security;
using Nop.Services.Stores;
using Nop.Web.Framework;
using Nop.Web.Framework.Controllers;
using System.Web.Mvc;

namespace Nop.Plugin.ExternalAuth.VK.Controllers
{
    public class ExternalAuthVKController : BasePluginController
    {
        private readonly ISettingService _settingService;
        private readonly IOAuthProviderVKAuthorizer _oAuthProviderVKAuthorizer;
        private readonly IOpenAuthenticationService _openAuthenticationService;
        private readonly ExternalAuthenticationSettings _externalAuthenticationSettings;
        private readonly IPermissionService _permissionService;
        private readonly IStoreContext _storeContext;
        private readonly IStoreService _storeService;
        private readonly IWorkContext _workContext;
        private readonly IPluginFinder _pluginFinder;

        public ExternalAuthVKController(ISettingService settingService,
            IOAuthProviderVKAuthorizer oAuthProviderVKAuthorizer,
            IOpenAuthenticationService openAuthenticationService,
            ExternalAuthenticationSettings externalAuthenticationSettings,
            IPermissionService permissionService,
            IStoreContext storeContext,
            IStoreService storeService,
            IWorkContext workContext,
            IPluginFinder pluginFinder)
        {
            this._settingService = settingService;
            this._oAuthProviderVKAuthorizer = oAuthProviderVKAuthorizer;
            this._openAuthenticationService = openAuthenticationService;
            this._externalAuthenticationSettings = externalAuthenticationSettings;
            this._permissionService = permissionService;
            this._storeContext = storeContext;
            this._storeService = storeService;
            this._workContext = workContext;
            this._pluginFinder = pluginFinder;
        }


        [AdminAuthorize]
        [ChildActionOnly]
        public ActionResult Configure()
        {
            if (!_permissionService.Authorize(StandardPermissionProvider.ManageExternalAuthenticationMethods))
                return Content("Access denied");

            //load settings for a chosen store scope
            var storeScope = this.GetActiveStoreScopeConfiguration(_storeService, _workContext);
            var VKExternalAuthSettings = _settingService.LoadSetting<VKExternalAuthSettings>(storeScope);

            var model = new ConfigurationModel();
            model.ClientKeyIdentifier = VKExternalAuthSettings.ClientKeyIdentifier;
            model.ClientSecret = VKExternalAuthSettings.ClientSecret;

            model.ActiveStoreScopeConfiguration = storeScope;
            if (storeScope > 0)
            {
                model.ClientKeyIdentifier_OverrideForStore = _settingService.SettingExists(VKExternalAuthSettings, x => x.ClientKeyIdentifier, storeScope);
                model.ClientSecret_OverrideForStore = _settingService.SettingExists(VKExternalAuthSettings, x => x.ClientSecret, storeScope);
            }

            return View("~/Plugins/ExternalAuth.VK/Views/ExternalAuthVK/Configure.cshtml", model);
        }

        [HttpPost]
        [AdminAuthorize]
        [ChildActionOnly]
        public ActionResult Configure(ConfigurationModel model)
        {
            if (!_permissionService.Authorize(StandardPermissionProvider.ManageExternalAuthenticationMethods))
                return Content("Access denied");

            if (!ModelState.IsValid)
                return Configure();

            //load settings for a chosen store scope
            var storeScope = this.GetActiveStoreScopeConfiguration(_storeService, _workContext);
            var VKExternalAuthSettings = _settingService.LoadSetting<VKExternalAuthSettings>(storeScope);

            //save settings
            VKExternalAuthSettings.ClientKeyIdentifier = model.ClientKeyIdentifier;
            VKExternalAuthSettings.ClientSecret = model.ClientSecret;

            /* We do not clear cache after each setting update.
             * This behavior can increase performance because cached settings will not be cleared 
             * and loaded from database after each update */
            if (model.ClientKeyIdentifier_OverrideForStore || storeScope == 0)
                _settingService.SaveSetting(VKExternalAuthSettings, x => x.ClientKeyIdentifier, storeScope, false);
            else if (storeScope > 0)
                _settingService.DeleteSetting(VKExternalAuthSettings, x => x.ClientKeyIdentifier, storeScope);

            if (model.ClientSecret_OverrideForStore || storeScope == 0)
                _settingService.SaveSetting(VKExternalAuthSettings, x => x.ClientSecret, storeScope, false);
            else if (storeScope > 0)
                _settingService.DeleteSetting(VKExternalAuthSettings, x => x.ClientSecret, storeScope);

            //now clear settings cache
            _settingService.ClearCache();

            return Configure();
        }

        [ChildActionOnly]
        public ActionResult PublicInfo()
        {
            return View("~/Plugins/ExternalAuth.VK/Views/ExternalAuthVK/PublicInfo.cshtml");
        }

        [NonAction]
        private ActionResult LoginInternal(string returnUrl, bool verifyResponse)
        {
            var processor = _openAuthenticationService.LoadExternalAuthenticationMethodBySystemName("ExternalAuth.VK");
            if (processor == null ||
                !processor.IsMethodActive(_externalAuthenticationSettings) ||
                !processor.PluginDescriptor.Installed ||
                !_pluginFinder.AuthenticateStore(processor.PluginDescriptor, _storeContext.CurrentStore.Id))
                throw new NopException("VK module cannot be loaded");

            var viewModel = new LoginModel();
            TryUpdateModel(viewModel);

            var result = _oAuthProviderVKAuthorizer.Authorize(returnUrl, verifyResponse);

            switch (result.AuthenticationStatus)
            {
                case OpenAuthenticationStatus.Error:
                    {
                        if (!result.Success)
                            foreach (var error in result.Errors)
                                ExternalAuthorizerHelper.AddErrorsToDisplay(error);

                        return new RedirectResult(Url.LogOn(returnUrl));
                    }
                case OpenAuthenticationStatus.AssociateOnLogon:
                    {
                        return new RedirectResult(Url.LogOn(returnUrl));
                    }
                case OpenAuthenticationStatus.AutoRegisteredEmailValidation:
                    {
                        return RedirectToRoute("RegisterResult", new { resultId = (int)UserRegistrationType.EmailValidation });
                    }
                case OpenAuthenticationStatus.AutoRegisteredAdminApproval:
                    {
                        return RedirectToRoute("RegisterResult", new { resultId = (int)UserRegistrationType.AdminApproval });
                    }
                case OpenAuthenticationStatus.AutoRegisteredStandard:
                    {
                        return RedirectToRoute("RegisterResult", new { resultId = (int)UserRegistrationType.Standard });
                    }
                default:
                    break;
            }

            if (result.Result != null) 
                return result.Result;

            return 
                HttpContext.Request.IsAuthenticated ? 
                    new RedirectResult(!string.IsNullOrEmpty(returnUrl) ? 
                        returnUrl : "~/") : 
                        new RedirectResult(Url.LogOn(returnUrl));

        }

        public ActionResult Login(string returnUrl)
        {
            return LoginInternal(returnUrl, false);
        }

        public ActionResult LoginCallback(string returnUrl)
        {
            return LoginInternal(returnUrl, true);
        }

    }
}
