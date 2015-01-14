using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.WeChat
{
    internal class WeChatAccountAuthenticationHandler : AuthenticationHandler<WeChatAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string AuthorizationEndpoint = "https://open.weixin.qq.com/connect/qrconnect";
        private const string TokenEndpoint = "https://api.weixin.qq.com/sns/oauth2/access_token";
        private const string UserInfoEndpoint = "https://api.weixin.qq.com/sns/userinfo";
        private const string OpenIDEndpoint = "https://api.weixin.qq.com/sns/oauth2";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public WeChatAccountAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this._httpClient = httpClient;
            this._logger = logger;
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Options.ReturnEndpointPath != null &&
                String.Equals(Options.ReturnEndpointPath, Request.Path.Value, StringComparison.OrdinalIgnoreCase))
            {
                return await InvokeReturnPathAsync();
            }
            return false;
        }

        private async Task<bool> InvokeReturnPathAsync()
        {
            _logger.WriteVerbose("InvokeReturnPath");

            var model = await AuthenticateAsync();

            var context = new WeChatReturnEndpointContext(Context, model);
            context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
            context.RedirectUri = model.Properties.RedirectUri;
			model.Properties.RedirectUri = null;

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                ClaimsIdentity signInIdentity = context.Identity;
                if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, signInIdentity);
            }

            if (!context.IsRequestCompleted && context.RedirectUri != null)
            {
                Response.Redirect(context.RedirectUri);
                context.RequestCompleted();
            }

            return context.IsRequestCompleted;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            _logger.WriteVerbose("AuthenticateCore");

            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var tokenRequestParameters = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("appid", Options.AppId),
                    new KeyValuePair<string, string>("secret", Options.AppSecret),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                };

                FormUrlEncodedContent requestContent = new FormUrlEncodedContent(tokenRequestParameters);

                HttpResponseMessage response = await _httpClient.PostAsync(TokenEndpoint, requestContent, Request.CallCancelled);
                response.EnsureSuccessStatusCode();
                string oauthTokenResponse = await response.Content.ReadAsStringAsync();
                JsonSerializer js = new JsonSerializer();
                AccessTokenResult tokenResult= js.Deserialize<AccessTokenResult>(new JsonTextReader(new System.IO.StringReader(oauthTokenResponse)));
                if (tokenResult == null || tokenResult.access_token == null)
                {
                    _logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }
                
                string userInfoUri = UserInfoEndpoint +
                    "?access_token=" + Uri.EscapeDataString(tokenResult.access_token) +
                    "&openid=" + Uri.EscapeDataString(tokenResult.openid);
                HttpResponseMessage userInfoResponse = await _httpClient.GetAsync(userInfoUri, Request.CallCancelled);
                userInfoResponse.EnsureSuccessStatusCode();
                string userInfoString = await userInfoResponse.Content.ReadAsStringAsync();
                JObject userInfo = JObject.Parse(userInfoString);

                var context = new WeChatAuthenticatedContext(Context, tokenResult.openid, userInfo, tokenResult.access_token);
                context.Identity = new ClaimsIdentity(new[]{
                    new Claim(ClaimTypes.NameIdentifier, context.Id,XmlSchemaString,Options.AuthenticationType),
                    new Claim(ClaimsIdentity.DefaultNameClaimType, context.Name,XmlSchemaString,Options.AuthenticationType),
                    new Claim("urn:wechatconnect:id", context.Id,XmlSchemaString,Options.AuthenticationType),
                    new Claim("urn:wechatconnect:name", context.Name,XmlSchemaString,Options.AuthenticationType),
                });

                await Options.Provider.Authenticated(context);

                context.Properties = properties;

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
            }

            return new AuthenticationTicket(null, properties);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            _logger.WriteVerbose("ApplyResponseChallenge");

            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string currentQueryString = Request.QueryString.Value;
                string currentUri = string.IsNullOrEmpty(currentQueryString)
                    ? requestPrefix + Request.PathBase + Request.Path
                    : requestPrefix + Request.PathBase + Request.Path + "?" + currentQueryString;

                string redirectUri = requestPrefix + Request.PathBase + Options.ReturnEndpointPath;

                AuthenticationProperties properties = challenge.Properties;

                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                // comma separated
                string scope = string.Join(",", Options.Scope);

                string state = Options.StateDataFormat.Protect(properties);

                string authorizationEndpoint =
                    AuthorizationEndpoint +
                        "?appid=" + Uri.EscapeDataString(Options.AppId ?? string.Empty) +
                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                        "&scope=" + Uri.EscapeDataString(scope) +
                        "&state=" + Uri.EscapeDataString(state) +
                        "&response_type=code";

                Response.Redirect(authorizationEndpoint);
            }

            return Task.FromResult<object>(null);
        }

        private string GenerateRedirectUri()
        {
            string requestPrefix = Request.Scheme + "://" + Request.Host;

            string redirectUri = requestPrefix + RequestPathBase + Options.ReturnEndpointPath; // + "?state=" + Uri.EscapeDataString(Options.StateDataFormat.Protect(state));            
            return redirectUri;
        }

        [Serializable]
        public class AccessTokenResult
        {
            public string errcode { get; set; }

            public string errmsg { get; set; }

            public string access_token { get; set; }

            public string expires_in { get; set; }

            public string refresh_token { get; set; }

            public string openid { get; set; }

            public string scope { get; set; }
        }
    }
}
