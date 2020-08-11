using System;
using Microsoft.Owin;
using Owin; 
using Microsoft.Owin.Security.OAuth;
using System.Web.Http;
using AngularAPI.Models;

[assembly: OwinStartup(typeof(AngularAPI.Startup))]

namespace AngularAPI
{
    public partial class Startup
    {
       // public static OAuthAuthorizationServerOptions OAuthOptions { get; private set; }
       
        public void Configuration(IAppBuilder app)
        {

             
        // Enable CORS (cross origin resource sharing) for making request using browser from different domains
             app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
            
             app.CreatePerOwinContext(ApplicationDbContext.Create);
             app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            PublicClientId = "self";
            OAuthAuthorizationServerOptions options = new OAuthAuthorizationServerOptions
            {
                AllowInsecureHttp = true,
                //The Path For generating the Toekn
                TokenEndpointPath = new PathString("/token"),
                //Setting the Token Expired Time (24 hours)
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(1),
                //MyAuthorizationServerProvider class will validate the user credentials
                Provider = new MyAuthorizationServerProvider(PublicClientId)
            };
            //Token Generations
            app.UseOAuthAuthorizationServer(options);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());

            HttpConfiguration config = new HttpConfiguration();
            WebApiConfig.Register(config);
        }
    }

}
