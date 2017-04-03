using DotNetOpenAuth.AspNet;
using DotNetOpenAuth.AspNet.Clients;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;

namespace Nop.Plugin.ExternalAuth.VK.OAuth2
{
    public class VKClient : OAuth2Client
    {
        private const string AuthorizationEndpoint = "https://oauth.vk.com/authorize";

        private const string TokenEndpoint = "https://oauth.vk.com/access_token";

        private const string UserInfoEndpoint = "https://api.vk.com/method/users.get";

        private readonly string[] UriRfc3986CharsToEscape = new string[] { "!", "*", "'", "(", ")" };

        private readonly string appId;

        private readonly string appSecret;

        private readonly string[] scope;

        private string email { get; set; }

        public VKClient(string appId, string appSecret)
            : this(appId, appSecret, "email")
        {
        }
 
       
        public VKClient(string appId, string appSecret, params string[] scope)
            : base("VK") {
          
            this.appId = appId;
            this.appSecret = appSecret;
            this.scope = scope;
        }

        private string HttpPost(string URI, string Parameters)
        {
            WebRequest req = WebRequest.Create(URI);
            req.ContentType = "application/x-www-form-urlencoded";
            req.Method = "POST";
            byte[] bytes = Encoding.UTF8.GetBytes(Parameters);
            req.ContentLength = bytes.Length;
            using (var stream = req.GetRequestStream())
            {
                stream.Write(bytes, 0, bytes.Length);
            }
            var res = (HttpWebResponse)req.GetResponse();
            using (var stream = res.GetResponseStream())
            {
                using (var reader = new StreamReader(stream))
                {
                    return reader.ReadToEnd().Trim();
                }
            }
        }

        public static string HttpGet(string URI, string Parameters)
        {
            URI += Parameters;
            var request = WebRequest.Create(URI) as HttpWebRequest;
            using (var response = request.GetResponse() as HttpWebResponse)
            {
                using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                {
                    return reader.ReadToEnd().Trim();
                }
            }
        }

        private string NormalizeHexEncoding(string url)
        {
            var chars = url.ToCharArray();
            for (int i = 0; i < chars.Length - 2; i++)
            {
                if (chars[i] == '%')
                {
                    chars[i + 1] = char.ToUpperInvariant(chars[i + 1]);
                    chars[i + 2] = char.ToUpperInvariant(chars[i + 2]);
                    i += 2;
                }
            }
            return new string(chars);
        }

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

        [Obsolete]
        protected override Uri GetServiceLoginUrl(Uri returnUrl)
        {
            var builder = new UriBuilder(AuthorizationEndpoint);
            var args = new Dictionary<string, string>();
            args.Add("response_type", "code");
            args.Add("client_id", appId);
            args.Add("redirect_uri", NormalizeHexEncoding(returnUrl.AbsoluteUri));
            args.Add("scope", "email");// string.Join(" ", this.scope));
            AppendQueryArgs(builder, args);
            return builder.Uri;
        }

        protected override IDictionary<string, string> GetUserData
            (string accessToken)
        {
            //GET https://api.vk.com/method/users.get?uids={user_id}
            //&fields=uid,first_name,last_name,nickname,screen_name,sex,bdate,city,country,timezone,photo&access_token={access_token}
            var userData = new Dictionary<string, string>();
            using (WebClient client = new WebClient())
            {
                using (Stream stream = client.OpenRead(UserInfoEndpoint
                    + "?access_token=" + EscapeUriDataStringRfc3986(accessToken)))
                    //+"&fields=uid,first_name,last_name,nickname,email&scope=email"))
                {
                    using (StreamReader reader = new StreamReader(stream))
                    {
                        JObject jObject = JObject.Parse(reader.ReadToEnd());
                        userData.Add("id", (string)jObject["response"][0]["uid"]);
                        userData.Add("username", this.email);// (string)jObject["response"][0]["first_name"]);
                        userData.Add("name", (string)jObject["response"][0]["last_name"] + " " + (string)jObject["response"][0]["first_name"]);
                    }
                }
            }

            return userData;
        }

        protected override string QueryAccessToken(Uri returnUrl, string authorizationCode)
        {
            // https://oauth.vk.com/access_token?client_id=1&client_secret=H2Pk8htyFD8024mZaPHm
            //&redirect_uri=http://mysite.ru&code=7a6fa4dff77a228eeda56603b8f53806c883f011c40b72630bb50df056f6479e52a
            var args = new Dictionary<string, string>();
            args.Add("client_id", appId);
            args.Add("client_secret", appSecret);
            args.Add("redirect_uri", NormalizeHexEncoding(returnUrl.AbsoluteUri));
            args.Add("scope", "email");

            //args.Add("response_type", "code");
            args.Add("code", authorizationCode);
            
            //args.Add("grant_type", "authorization_code");
            string query = "?" + CreateQueryString(args);
            string data = HttpGet(TokenEndpoint, query);
            if (string.IsNullOrEmpty(data))
                return null;
            JObject jObject = JObject.Parse(data);
            this.email = (String)jObject["email"];
            return (string)jObject["access_token"];                  
        }
    }
}
