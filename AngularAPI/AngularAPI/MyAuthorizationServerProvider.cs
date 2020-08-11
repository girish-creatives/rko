using AngularAPI.Models;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using AngularAPI.Models;
using FileLogger;

namespace AngularAPI
{

    public class MyAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        FileLogger.FileLogger logger = FileLogger.FileLogger.SingleInstance;

        // UserMasterRepository _repo = new UserMasterRepository();

        private readonly string _publicClientId;

        public MyAuthorizationServerProvider(string publicClientId)
        {
            try
            {
                logger.LogMessage("Controller:- MyAuthorizationSErviceProvoder, MethodName:-MyAuthorizationServerProvider", MessageType.Info);

                if (publicClientId == null)
                {
                    throw new ArgumentNullException("publicClientId");
                }

                _publicClientId = publicClientId;
                logger.LogMessage("Controller:- MyAuthorizationSErviceProvoder, MethodName:-MyAuthorizationServerProvider", MessageType.Success);

            }
            catch (Exception ex)
            {
                logger.LogMessage("Controller:- MyAuthorizationSErviceProvoder, MethodName:-MyAuthorizationServerProvider, Error:-" + ex.Message +"At line :-" + ex.StackTrace, MessageType.Error);

                 
            }
           
        }


        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            // var user = _repo.ValidateUser(context);
            ////  if (user == null)
            ////  {
            ////      context.SetError("invalid_grant", "Provided username and password is incorrect");
            ////      return;
            ////  }
            ////  var identity = new ClaimsIdentity(context.Options.AuthenticationType); 
            ////  context.Validated(identity);
            ///
            try
            {
                logger.LogMessage("Controller:- MyAuthorizationSErviceProvoder, MethodName:-GrantResourceOwnerCredentials", MessageType.Info);

                var userManager = context.OwinContext.GetUserManager<ApplicationUserManager>();

                ApplicationUser user = await userManager.FindAsync(context.UserName, context.Password);

                if (user == null)
                {
                    context.SetError("invalid_grant", "The user name or password is incorrect.");
                    logger.LogMessage("Controller:- MyAuthorizationSErviceProvoder, MethodName:-GrantResourceOwnerCredentials , Message:- No record found", MessageType.Warning);

                    return;
                }

                ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(userManager,
                   OAuthDefaults.AuthenticationType);
                ClaimsIdentity cookiesIdentity = await user.GenerateUserIdentityAsync(userManager,
                    CookieAuthenticationDefaults.AuthenticationType);

                AuthenticationProperties properties = CreateProperties(user.UserName);
                AuthenticationTicket ticket = new AuthenticationTicket(oAuthIdentity, properties);
                context.Validated(ticket);
                context.Request.Context.Authentication.SignIn(cookiesIdentity);
                logger.LogMessage("Controller:- MyAuthorizationSErviceProvoder, MethodName:-GrantResourceOwnerCredentials", MessageType.Success);


            }
            catch (Exception ex)
            {
                logger.LogMessage("Controller:- MyAuthorizationSErviceProvoder, MethodName:-GrantResourceOwnerCredentials, Error:-" + ex.Message + "At line :-" + ex.StackTrace, MessageType.Error);

                //throw ex;
            }
           
        }


        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }

        

        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            if (context.ClientId == _publicClientId)
            {
                Uri expectedRootUri = new Uri(context.Request.Uri, "/");

                if (expectedRootUri.AbsoluteUri == context.RedirectUri)
                {
                    context.Validated();
                }
            }

            return Task.FromResult<object>(null);
        }

        public static AuthenticationProperties CreateProperties(string userName)
        {
            IDictionary<string, string> data = new Dictionary<string, string>
            {
                { "userName", userName }
            };
            return new AuthenticationProperties(data);
        }
    }


}
