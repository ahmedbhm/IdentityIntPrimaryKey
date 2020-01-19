using IdentityIntPrimaryKey.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace IdentityIntPrimaryKey
{
    public class ApplicationOAuthProvider : OAuthAuthorizationServerProvider
    {
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
        }
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var userStore = new CustomUserStore(new ApplicationDbContext());
            var manager = new ApplicationUserManager(userStore);
            var user = await manager.FindAsync(context.UserName, context.Password);
            if (user != null)
            {
                var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                identity.AddClaim(new Claim("Username", user.UserName));
                identity.AddClaim(new Claim("LoggedOn", DateTime.Now.ToString()));
                identity.AddClaim(new Claim("Id", user.Id.ToString()));
                var userRoles = manager.GetRoles(user.Id);
                var additionalData = new AuthenticationProperties(new Dictionary<string, string>() { 
                  {"Id",user.Id.ToString()},
                   {"Username", user.UserName},
                    {"role", Newtonsoft.Json.JsonConvert.SerializeObject(userRoles)}
                });
                var token = new AuthenticationTicket(identity, additionalData);
                context.Validated(token);
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