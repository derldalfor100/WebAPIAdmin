using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Cors;
using Microsoft.Owin.Security.OAuth;

[assembly: OwinStartup(typeof(WebAPI.Startup))]

namespace WebAPI
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=316888

            app.UseCors(CorsOptions.AllowAll);

            OAuthAuthorizationServerOptions option = new OAuthAuthorizationServerOptions
            {// like a controller
                TokenEndpointPath = new PathString("/token"),// go to the URL: "/token" to do Token based authentication
                Provider = new ApplicationOAuthProvider(),// to autheticate with ApplicationOAuthProvider; if we've a match
                // then: the Provider creates a token
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(60),// allow the given encoded string to exist only 60 min
                AllowInsecureHttp = true// for this project no need for secured Http
            };
            app.UseOAuthAuthorizationServer(option);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
            // Enable the application to use bearer tokens to authenticate users
        }
    }
}
