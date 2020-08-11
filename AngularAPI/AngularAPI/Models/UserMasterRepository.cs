using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AngularAPI.Models
{
    public class UserMasterRepository
    {
        ApplicationDbContext db = new ApplicationDbContext();
        public object ValidateUser(OAuthGrantResourceOwnerCredentialsContext context)
        {
            try
            {
                var data = db.Users.Where(x => x.Email == context.UserName ).FirstOrDefault();
                return data;
            }
            catch (Exception ex)
            {

                throw ex;
            }
           
        }
    }
}