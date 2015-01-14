using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.WeChat
{
    public class WeChatAuthenticationProvider : IWeChatAuthenticationProvider
    {
        public WeChatAuthenticationProvider()
        {
            onAuthenticated = (c) => Task.FromResult<WeChatAuthenticatedContext>(null);
            onReturnEndpoint = (c) => Task.FromResult<WeChatReturnEndpointContext>(null);
        }

        public Func<WeChatAuthenticatedContext, Task> onAuthenticated { get; set; }
        public Func<WeChatReturnEndpointContext, Task> onReturnEndpoint { get; set; }

        public Task Authenticated(WeChatAuthenticatedContext context)
        {
            return onAuthenticated(context);
        }

        public Task ReturnEndpoint(WeChatReturnEndpointContext context)
        {
            return onReturnEndpoint(context);
        }
    }
}
