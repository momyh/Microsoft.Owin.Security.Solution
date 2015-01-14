using System;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace Microsoft.Owin.Security.WeChat
{
    public class WeChatAuthenticationMiddleware :AuthenticationMiddleware<WeChatAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public WeChatAuthenticationMiddleware(
            OwinMiddleware next,
            IAppBuilder app,
            WeChatAuthenticationOptions options)
            : base(next, options)
        {
            _logger = app.CreateLogger<WeChatAuthenticationOptions>();

            if (Options.Provider == null)
            {
                Options.Provider = new WeChatAuthenticationProvider();
            }
            if (Options.StateDataFormat == null)
            {
                var dataProtecter = app.CreateDataProtector(
                    typeof(WeChatAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtecter);
            }

            _httpClient = new HttpClient(ResolveHttpMessageHandler(Options));
            _httpClient.Timeout = Options.BackchannelTimeout;
            _httpClient.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
        }

        protected override AuthenticationHandler<WeChatAuthenticationOptions> CreateHandler()
        {
            return new WeChatAccountAuthenticationHandler(_httpClient, _logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(WeChatAuthenticationOptions options)
        {
            HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                WebRequestHandler webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("An ICertificateValidator cannot be specified at the same time as an HttpMessageHandler unless it is a WebRequestHandler.");
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }
    }
}
