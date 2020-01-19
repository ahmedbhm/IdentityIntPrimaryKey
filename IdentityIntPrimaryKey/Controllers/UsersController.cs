using IdentityIntPrimaryKey.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Web.Http;

namespace IdentityIntPrimaryKey.Controllers
{
    public class UsersController : ApiController
    {
        [Route("api/User/Register")]
        [HttpPost]
        [AllowAnonymous]
        public HttpResponseMessage Register(String username, String password, String role)
        {
            var manager = new ApplicationUserManager(new CustomUserStore(new ApplicationDbContext()));

            if (manager.FindByName(username) != null)     return this.Request.CreateResponse(HttpStatusCode.NotAcceptable, "username exist");
            if (manager.FindByEmail("aa@ff.com") != null) return this.Request.CreateResponse(HttpStatusCode.NotAcceptable, "Email exist");
            if (password.Length < 8)                      return this.Request.CreateResponse(HttpStatusCode.NotAcceptable, "RequiredLength = 8");

            var user = new ApplicationUser() { UserName = username };
            var result = manager.Create(user, password);
            if (result.Succeeded) manager.AddToRoles(user.Id, role);
            return this.Request.CreateResponse(HttpStatusCode.OK, result);
        }
        [Route("api/Role/Add")]
        [HttpPost]
        [AllowAnonymous]
        public HttpResponseMessage AddRole(String Role)
        {
            var RoleManager = new ApplicationRoleManager(new CustomRoleStore(new ApplicationDbContext()));
            IdentityResult roleResult;
            // Check to see if Role Exists, if not create it
            if (!RoleManager.RoleExists(Role))
            {
                roleResult = RoleManager.Create(new CustomRole(Role));
                return this.Request.CreateResponse(HttpStatusCode.OK, roleResult);
            }
            return this.Request.CreateResponse(HttpStatusCode.OK, "role exist");
        }

        [Route("api/Roles/{userid}")]
        [HttpGet]
        [AllowAnonymous]
        public HttpResponseMessage Roles(int userid)
        {
            var manager = new ApplicationUserManager(new CustomUserStore(new ApplicationDbContext()));
            List<string> userRoles = manager.GetRoles(userid).ToList();
            return this.Request.CreateResponse(HttpStatusCode.OK, userRoles);
        }
        [Route("api/Roles/removeAll/{userid}")]
        [HttpPost]
        [AllowAnonymous]
        public HttpResponseMessage removeAll(int userid)
        {
            var manager = new ApplicationUserManager(new CustomUserStore(new ApplicationDbContext()));
            List<string> userRoles = manager.GetRoles(userid).ToList();
            userRoles.ForEach(delegate(String role) { manager.RemoveFromRole(userid, role); });
            return this.Request.CreateResponse(HttpStatusCode.OK);
        }

        [Route("api/Users/changepass/{userid}")]
        [HttpPost]
        [AllowAnonymous]
        public HttpResponseMessage removeAll(int userid,String newpass)
        {
          var userstore=new CustomUserStore(new ApplicationDbContext());
          var manager = new ApplicationUserManager(userstore);

          PasswordValidator p = new PasswordValidator{RequiredLength = 8};
          var passwordResult = p.ValidateAsync(newpass);
          if(!passwordResult.Result.Succeeded) return this.Request.CreateResponse(HttpStatusCode.OK,passwordResult);
          
           var newPasswordHash = manager.PasswordHasher.HashPassword(newpass);
           ApplicationUser cUser = manager.FindById(userid);
           userstore.SetPasswordHashAsync(cUser,newPasswordHash);
           userstore.UpdateAsync(cUser);
           return this.Request.CreateResponse(HttpStatusCode.OK, IdentityResult.Success);
        }
        [Route("api/Users/update")]
        [HttpPost]
        [AllowAnonymous]
        public HttpResponseMessage update(int userid)
        {
            var userstore = new CustomUserStore(new ApplicationDbContext());
            var manager = new ApplicationUserManager(userstore);

            ApplicationUser user = manager.FindById(userid);
            /*
            // Update it with the values from the view model
            user.Name = model.Name;
            user.Surname = model.Surname;
            user.UserName = model.UserName;
            user.Email = model.Email;
            user.PhoneNumber = model.PhoneNumber;
            user.PasswordHash = checkUser.PasswordHash;
            manager.Update(user);
            */
            return this.Request.CreateResponse(HttpStatusCode.OK, IdentityResult.Success);
        }
        [Route("api/Users")]
        [HttpGet]
        [AllowAnonymous]
        public HttpResponseMessage get()
        {
          return this.Request.CreateResponse(HttpStatusCode.OK, "test");
        }
    }
}
