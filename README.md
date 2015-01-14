# Microsoft.Owin.Security.Solution is the asp.net mvc5 solution extentions for china developer

this solution is the Microsoft.Owin.Security extention,is extention the china qq and weixin login with asp.net identity

How to use:
Add below code to asp.net mvc5 project App_Start/Startup.Auth.cs

app.UseQQConnectAuthentication(appId: "***",appSecret: "*****");

app.UseWeChatAuthentication(appId: "***",appSecret: "*****");

这个工程系对asp.net identity的一个扩展，在asp.net mvc5的基础上增加了中国国内的QQ和微信登陆，用于解决新网站集成这两种登陆方式的麻烦，欢迎其他人员贡献代码。

