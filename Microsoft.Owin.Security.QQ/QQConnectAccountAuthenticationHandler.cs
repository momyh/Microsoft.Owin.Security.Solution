/*
 *  Copyright 2013 Feifan Tang. All rights reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.WeChat
{
    internal class QQConnectAccountAuthenticationHandler : AuthenticationHandler<QQConnectAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string AuthorizationEndpoint = "https://graph.qq.com/oauth2.0/authorize";
        private const string TokenEndpoint = "https://graph.qq.com/oauth2.0/token";
        private const string UserInfoEndpoint = "https://openmobile.qq.com/user/get_simple_userinfo";
        private const string OpenIDEndpoint = "https://graph.qq.com/oauth2.0/me";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public QQConnectAccountAuthenticationHandler(HttpClient httpClient, ILogger logger)
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

            var context = new QQConnectReturnEndpointContext(Context, model);
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
                    new KeyValuePair<string, string>("client_id", Options.AppId),
                    new KeyValuePair<string, string>("client_secret", Options.AppSecret),
                    new KeyValuePair<string, string>("redirect_uri", GenerateRedirectUri()),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                };

                FormUrlEncodedContent requestContent = new FormUrlEncodedContent(tokenRequestParameters);

                HttpResponseMessage response = await _httpClient.PostAsync(TokenEndpoint, requestContent, Request.CallCancelled);
                response.EnsureSuccessStatusCode();
                string oauthTokenResponse = await response.Content.ReadAsStringAsync();
                var tokenDict = QueryStringToDict(oauthTokenResponse);

                string accessToken = null;
                if(tokenDict.ContainsKey("access_token"))
                {
                    accessToken = tokenDict["access_token"];
                }
                else
                {
                    _logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }

                string openIDUri = OpenIDEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken);
                HttpResponseMessage openIDResponse = await _httpClient.GetAsync(openIDUri, Request.CallCancelled);
                openIDResponse.EnsureSuccessStatusCode();
                string openIDString = await openIDResponse.Content.ReadAsStringAsync();
                openIDString = ExtractOpenIDCallbackBody(openIDString);
                JObject openIDInfo = JObject.Parse(openIDString);

                var clientId = openIDInfo["client_id"].Value<string>();
                var openId = openIDInfo["openid"].Value<string>();

                string userInfoUri = UserInfoEndpoint +
                    "?access_token=" + Uri.EscapeDataString(accessToken) +
                    "&oauth_consumer_key=" + Uri.EscapeDataString(clientId) +
                    "&openid=" + Uri.EscapeDataString(openId);
                HttpResponseMessage userInfoResponse = await _httpClient.GetAsync(userInfoUri, Request.CallCancelled);
                userInfoResponse.EnsureSuccessStatusCode();
                string userInfoString = await userInfoResponse.Content.ReadAsStringAsync();
                JObject userInfo = JObject.Parse(userInfoString);

                var context = new QQConnectAuthenticatedContext(Context, openId, userInfo, accessToken);
                context.Identity = new ClaimsIdentity(new[]{
                    new Claim(ClaimTypes.NameIdentifier, context.Id,XmlSchemaString,Options.AuthenticationType),
                    new Claim(ClaimsIdentity.DefaultNameClaimType, context.Name,XmlSchemaString,Options.AuthenticationType),
                    new Claim("urn:qqconnect:id", context.Id,XmlSchemaString,Options.AuthenticationType),
                    new Claim("urn:qqconnect:name", context.Name,XmlSchemaString,Options.AuthenticationType),
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
                        "?client_id=" + Uri.EscapeDataString(Options.AppId ?? string.Empty) +
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

        private string ExtractOpenIDCallbackBody(string callbackString)
        {
            int leftBracketIndex = callbackString.IndexOf('{');
            int rightBracketIndex = callbackString.IndexOf('}');
            if (leftBracketIndex >= 0 && rightBracketIndex >= 0)
            {
                return callbackString.Substring(leftBracketIndex, rightBracketIndex - leftBracketIndex + 1).Trim();
            }
            return callbackString;
        }

        private IDictionary<string,string> QueryStringToDict(string str)
        {
            var strArr = str.Split('&');
            var dict = new Dictionary<string, string>(strArr.Length);
            foreach(var s in strArr)
            {
                var equalSymbolIndex = s.IndexOf('=');
                if(equalSymbolIndex>0&&equalSymbolIndex<s.Length-1)
                {
                    dict.Add(
                        s.Substring(0,equalSymbolIndex), 
                        s.Substring(equalSymbolIndex+1,s.Length-equalSymbolIndex-1));
                }
            }
            return dict;
        }
    }
}
