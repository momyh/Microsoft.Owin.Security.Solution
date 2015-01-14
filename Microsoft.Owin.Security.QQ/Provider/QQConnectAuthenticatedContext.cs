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
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.WeChat
{
    public class QQConnectAuthenticatedContext : BaseContext
    {
        public QQConnectAuthenticatedContext(IOwinContext context,string openId, JObject user, string accessToken)
            :base(context)
        {
            IDictionary<string, JToken> userAsDictionary = user;

            User = user;
            AccessToken = accessToken;

            Id = openId;
            Name = PropertyValueIfExists("nickname", userAsDictionary);
        }

        public JObject User { get; private set; }
        public string AccessToken { get; private set; }

        public string Id { get; private set; }
        public string Name { get; private set; }

        public ClaimsIdentity Identity { get; set; }
        public AuthenticationProperties Properties { get; set; }

        private static string PropertyValueIfExists(string property, IDictionary<string, JToken> dictionary)
        {
            return dictionary.ContainsKey(property) ? dictionary[property].ToString() : null;
        }
    }
}
