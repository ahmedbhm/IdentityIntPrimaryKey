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
            var userStore = new CustomUserStore(new ApplicationDbContext());
            var manager = new ApplicationUserManager(userStore);
            var user = new ApplicationUser() { UserName = username };
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 8
            };
            var result = manager.Create(user, password);
            manager.AddToRoles(user.Id, role);
            return this.Request.CreateResponse(HttpStatusCode.OK, result);

           // var RoleManager = new RoleManager(new CustomUserStore(new ApplicationDbContext()));
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
        [Route("api/Users")]
        [HttpGet]
        [AllowAnonymous]
        public HttpResponseMessage get()
        {
          return this.Request.CreateResponse(HttpStatusCode.OK, "test");
        }
    }
}
