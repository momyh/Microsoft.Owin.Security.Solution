using System;
using Microsoft.Owin.Security.WeChat;
using Microsoft.Owin.Security;

namespace Owin
{
    public static class WeChatAuthenticationExtensions
    {
        public static void UseWeChatAuthentication(this IAppBuilder app, WeChatAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(WeChatAuthenticationMiddleware), app, options);
        }

        public static void UseWeChatAuthentication(this IAppBuilder app, string appId, string appSecret)
        {
            UseWeChatAuthentication(app, new WeChatAuthenticationOptions()
            {
                AppId = appId,
                AppSecret = appSecret,
                SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType()
            });
        }
    }
}
