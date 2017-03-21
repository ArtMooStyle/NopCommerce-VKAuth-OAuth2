using DotNetOpenAuth.AspNet;
using Nop.Core;
using Nop.Core.Domain.Customers;
using Nop.Plugin.ExternalAuth.VK.OAuth2;
using Nop.Services.Authentication.External;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace Nop.Plugin.ExternalAuth.VK.Core
{
    public class VKProviderAuthorizer : IOAuthProviderVKAuthorizer
    {
        private readonly IExternalAuthorizer _authorizer;
        private readonly ExternalAuthenticationSettings _externalAuthenticationSettings;
        private readonly VKExternalAuthSettings _VKExternalAuthSettings;
        private readonly HttpContextBase _httpContext;
        private readonly IWebHelper _webHelper;
        private VKClient _VKApplication;

        public VKProviderAuthorizer(
            IExternalAuthorizer authorizer,
            ExternalAuthenticationSettings externalAuthenticationSettings,
            VKExternalAuthSettings VKExternalAuthSettings,
            HttpContextBase httpContext,
            IWebHelper webHelper)
        {
            this._authorizer = authorizer;
            this._externalAuthenticationSettings = externalAuthenticationSettings;
            this._VKExternalAuthSettings = VKExternalAuthSettings;
            this._httpContext = httpContext;
            this._webHelper = webHelper;
        }

        private VKClient VKApplication
        {
            get { return _VKApplication ?? 
                    (_VKApplication = 
                    new VKClient(_VKExternalAuthSettings.ClientKeyIdentifier, 
                    _VKExternalAuthSettings.ClientSecret)); }
        }

        private readonly string[] UriRfc3986CharsToEscape = new string[] { "!", "*", "'", "(", ")" };
        
        private string EscapeUriDataStringRfc3986(string value)
        {
            StringBuilder builder = new StringBuilder(Uri.EscapeDataString(value));
            for (int i = 0; i < UriRfc3986CharsToEscape.Length; i++)
            {
                builder.Replace(UriRfc3986CharsToEscape[i], Uri.HexEscape(UriRfc3986CharsToEscape[i][0]));
            }
            return builder.ToString();
        }

        private string CreateQueryString(IEnumerable<KeyValuePair<string, string>> args)
        {
            if (!args.Any<KeyValuePair<string, string>>())
            {
                return string.Empty;
            }
            StringBuilder builder = new StringBuilder(args.Count<KeyValuePair<string, string>>() * 10);
            foreach (KeyValuePair<string, string> pair in args)
            {
                builder.Append(EscapeUriDataStringRfc3986(pair.Key));
                builder.Append('=');
                builder.Append(EscapeUriDataStringRfc3986(pair.Value));
                builder.Append('&');
            }
            builder.Length--;
            return builder.ToString();
        }

        private void AppendQueryArgs(UriBuilder builder, IEnumerable<KeyValuePair<string, string>> args)
        {
            if ((args != null) && (args.Count<KeyValuePair<string, string>>() > 0))
            {
                StringBuilder builder2 = new StringBuilder(50 + (args.Count<KeyValuePair<string, string>>() * 10));
                if (!string.IsNullOrEmpty(builder.Query))
                {
                    builder2.Append(builder.Query.Substring(1));
                    builder2.Append('&');
                }
                builder2.Append(CreateQueryString(args));
                builder.Query = builder2.ToString();
            }
        }

        private Uri GenerateLocalCallbackUri()
        {
            string url = string.Format("{0}plugins/externalauthVK/logincallback/", _webHelper.GetStoreLocation());
            return new Uri(url);
        }

        private Uri GenerateServiceLoginUrl()
        {
            // http://oauth.vk.com/authorize?client_id={client_id}&redirect_uri=mysite.com/vklogin&response_type=code

            var builder = new UriBuilder("http://oauth.vk.com/authorize");
            var args = new Dictionary<string, string>();
            args.Add("response_type", "code");
            args.Add("client_id", _VKExternalAuthSettings.ClientKeyIdentifier);
            args.Add("redirect_uri", GenerateLocalCallbackUri().AbsoluteUri);
            args.Add("scope", "email");
            //args.Add("scope", "https://www.VKapis.com/auth/userinfo.profile https://www.VKapis.com/auth/userinfo.email");
            AppendQueryArgs(builder, args);
            return builder.Uri;
        }

        private void ParseClaims(AuthenticationResult authenticationResult, OAuthAuthenticationParameters parameters)
        {
            var claims = new UserClaims();
            claims.Contact = new ContactClaims();
            if (authenticationResult.ExtraData.ContainsKey("username"))
                claims.Contact.Email = authenticationResult.ExtraData["username"];
            claims.Name = new NameClaims();
            if (authenticationResult.ExtraData.ContainsKey("name"))
            {
                var name = authenticationResult.ExtraData["name"];
                if (!String.IsNullOrEmpty(name))
                {
                    var nameSplit = name.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (nameSplit.Length >= 2)
                    {
                        claims.Name.First = nameSplit[0];
                        claims.Name.Last = nameSplit[1];
                    }
                    else
                    {
                        claims.Name.Last = nameSplit[0];
                    }
                }
            }

            parameters.AddClaim(claims);
        }

        private AuthorizeState VerifyAuthentication(string returnUrl)
        {
            var authResult = VKApplication.VerifyAuthentication(_httpContext, GenerateLocalCallbackUri());

            if (authResult.IsSuccessful)
            {
                if (!authResult.ExtraData.ContainsKey("id"))
                    throw new Exception("Authentication result does not contain id data");

                if (!authResult.ExtraData.ContainsKey("accesstoken"))
                    throw new Exception("Authentication result does not contain accesstoken data");

                var parameters = new OAuthAuthenticationParameters(Provider.SystemName)
                {
                    ExternalIdentifier = authResult.ProviderUserId,
                    OAuthToken = authResult.ExtraData["accesstoken"],
                    OAuthAccessToken = authResult.ProviderUserId,
                };

                if (_externalAuthenticationSettings.AutoRegisterEnabled)
                    ParseClaims(authResult, parameters);

                var result = _authorizer.Authorize(parameters);

                return new AuthorizeState(returnUrl, result);
            }

            var state = new AuthorizeState(returnUrl, OpenAuthenticationStatus.Error);
            var error = authResult.Error != null ? authResult.Error.Message : "Unknown error";
            state.AddError(error);
            return state;
        }

        private AuthorizeState RequestAuthentication(string returnUrl)
        {
            var authUrl = GenerateServiceLoginUrl().AbsoluteUri;
            return new AuthorizeState("", OpenAuthenticationStatus.RequiresRedirect) { Result = new RedirectResult(authUrl) };
        }

        public AuthorizeState Authorize(string returnUrl, bool? verifyResponse = null)
        {
            if (!verifyResponse.HasValue)
                throw new ArgumentException("VK plugin cannot automatically determine verifyResponse property");

            if (verifyResponse.Value)
            {
                return VerifyAuthentication(returnUrl);
            }
            else
            {
                return RequestAuthentication(returnUrl);
            }
        }
    }
}