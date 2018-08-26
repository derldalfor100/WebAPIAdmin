using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using WebAPI.Models;

namespace WebAPI
{
    public class ApplicationOAuthProvider : OAuthAuthorizationServerProvider
    {

        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {// we don't need to validate user device!
            context.Validated();
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {// give info about how to authenticate user, with user name and user id of context -> from the user input in the Front-Side
            var userStore = new UserStore<ApplicationUser>(new ApplicationDbContext());// data-base
            var manager = new UserManager<ApplicationUser>(userStore);// as the manager of the db
            var user = await manager.FindAsync(context.UserName,context.Password);// inside context we've UserName and Password
            // this method wait till the manger'd found a match or null if there's no match
            if (user != null) {// therefore if user != null then we've a match between the correct username and the correct password
                var identity = new ClaimsIdentity(context.Options.AuthenticationType);// deafault - for make an identity
                identity.AddClaim(new Claim("Username", user.UserName));// we can also use context.UserName
                identity.AddClaim(new Claim("Email", user.Email));
                identity.AddClaim(new Claim("FirstName", user.FirstName));
                identity.AddClaim(new Claim("LastName", user.LastName));
                identity.AddClaim(new Claim("LoggedOn", DateTime.Now.ToString()));
                //identity.AddClaim(new Claim(ClaimTypes.Role, "user"));
                var userRoles = manager.GetRoles(user.Id);// get the user's roles
                foreach (string roleName in userRoles)
                {// add as an additional info
                    identity.AddClaim(new Claim(ClaimTypes.Role, roleName));
                }
                var additionalData = new AuthenticationProperties(new Dictionary<string, string>{
                    { // convert to Json
                        "role", Newtonsoft.Json.JsonConvert.SerializeObject(userRoles)
                    }
                });
                var token = new AuthenticationTicket(identity, additionalData);
                context.Validated(token);// marks the identity and additionalData as validated
            }
            else
                return;
        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }
    }
}