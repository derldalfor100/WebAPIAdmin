using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using WebAPI.Models;

namespace WebAPI.Controllers
{
    public class AccountController : ApiController
    {
        [Route("api/User/Register")]
        [HttpPost]
        [AllowAnonymous]
        public IdentityResult Register(AccountModel model)
        {
            var userStore = new UserStore<ApplicationUser>(new ApplicationDbContext());// because ApplicationDbContext
            var manager = new UserManager<ApplicationUser>(userStore);
            var user = new ApplicationUser() { UserName = model.UserName, Email = model.Email };
            user.FirstName = model.FirstName;
            user.LastName = model.LastName;
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 3
            };
            IdentityResult result = manager.Create(user, model.Password);
            //manager.Users.ToList();// to get a list of the users

            //Example for put (update) script
            //var selectedUser = manager.FindByName("derldalfor");// should get username as an input
            //selectedUser.LastName = "Flores";// change the surname
            //selectedUser.Roles.Remove(selectedUser.Roles.ElementAt(0));
            //manager.RemoveFromRole(selectedUser.Id, "Consumer");// remove from UserRole table the old entry
            //manager.AddToRoles(selectedUser.Id, "Admin");// add the new entry into UserRole
            //manager.ResetPassword(selectedUser.Id, selectedUser.SecurityStamp, "w1000");// it looks like we don't have a need for that
            //IdentityResult result2 = UserManagerExtensions.ChangePassword(manager, selectedUser.Id, "w102030", "w1000");// change the password to w1000 and set the result (everything is OK or not)


            manager.AddToRoles(user.Id, model.Roles);
            return result;
        }

        [HttpGet]
        [Route("api/GetUserClaims")]
        public AccountModel GetUserClaims()
        {
            var identityClaims = (ClaimsIdentity)User.Identity;
            IEnumerable<Claim> claims = identityClaims.Claims;
            AccountModel model = new AccountModel()
            {// to add all those additional info 
                UserName = identityClaims.FindFirst("Username").Value,
                Email = identityClaims.FindFirst("Email").Value,
                FirstName = identityClaims.FindFirst("FirstName").Value,
                LastName = identityClaims.FindFirst("LastName").Value,
                LoggedOn = identityClaims.FindFirst("LoggedOn").Value,
            };
            return model;
        }

        [HttpGet]
        [Authorize(Roles = "Admin")]
        [Route("api/GetUser/{name}")]
        public AccountModel GetUser([FromUri()] string name)
        {
            var userStore = new UserStore<ApplicationUser>(new ApplicationDbContext());// because ApplicationDbContext
            var manager = new UserManager<ApplicationUser>(userStore);
            //List<ApplicationUser> users = manager.Users.ToList();// to get a list of all the users
            var user = manager.FindByName(name);// find the user by username
            var identityClaims = (ClaimsIdentity)User.Identity;
            IEnumerable<Claim> claims = identityClaims.Claims;
            AccountModel model = new AccountModel()
            {// to add all those additional info 
                UserName = user.UserName,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Roles = new string[user.Roles.ToArray().Length]
            };
            for (int i = 0; i < user.Roles.ToArray().Length; i++)
            {
                if (user.Roles.ToArray()[i].RoleId.Equals("1"))
                {
                    model.Roles[i] = "Admin";
                }
                else
                {
                    model.Roles[i] = "Consumer";
                }
            }

            return model;
        }

        [HttpGet]
        [Authorize(Roles = "Admin")]
        [Route("api/ForAdminRole")]
        public string ForAdminRole()
        {
            return "for admin role";
        }

        [HttpGet]
        [Authorize(Roles = "Consumer")]
        [Route("api/ForConsumer")]
        public string ForAuthorOrReader()
        {
            return "For consumer role";
        }
        
        [HttpPut]
        [Authorize(Roles = "Admin")]
        [Route("api/update/{name}/{flag:int}/{param}")]
        public IdentityResult Update([FromUri()] string name, [FromUri()] int flag, [FromUri()] string param)
        {
            var userStore = new UserStore<ApplicationUser>(new ApplicationDbContext());// because ApplicationDbContext
            var manager = new UserManager<ApplicationUser>(userStore);// use the manager to control
            var user = manager.FindByName(name);// find the user by username

            switch (flag)
            {
                case 1:
                    manager.AddToRoles(user.Id, "Admin");// change the role to Admin
                    break;
                case 2:
                    manager.AddToRoles(user.Id, "Consumer");// change the role to Consumer
                    break;
                case 3:
                    user.FirstName = param;
                    break;
                case 4:
                    user.LastName = param;
                    break;
                case 5:
                    manager.PasswordValidator = new PasswordValidator
                    {
                        RequiredLength = 3
                    };
                    break;
                case 6:
                    user.Email = param;
                    break;
                case 7:
                    user.UserName = param;
                    break;
                case 8:

                    //user.Roles.ToArray()[0].RoleId = "2";
                    //System.Web.Security.Roles.AddUserToRole(name, "Consumer");
                    if(param.Equals("Admin"))
                        manager.AddToRole(user.Id, "Consumer");
                    else
                        manager.AddToRole(user.Id, "Admin");
                    break;
            }
            

            IdentityResult result = manager.Update(user);

        
            return result;
        }

        [HttpDelete]
        [Authorize(Roles = "Admin")]
        [Route("api/DeleteUser/{name}")]
        public IdentityResult DeleteUser([FromUri()] string name)
        {
            var userStore = new UserStore<ApplicationUser>(new ApplicationDbContext());// because ApplicationDbContext
            var manager = new UserManager<ApplicationUser>(userStore);// use the manager to control
            var user = manager.FindByName(name);// find the user by username
            IdentityResult result = manager.Delete(user);
            return result;
        }

        [HttpDelete]
        [Authorize(Roles = "Admin")]
        [Route("api/DeleteRole/{name}")]
        public IdentityResult DeleteRole([FromUri()] string name)
        {
            var userStore = new UserStore<ApplicationUser>(new ApplicationDbContext());// because ApplicationDbContext
            var manager = new UserManager<ApplicationUser>(userStore);// use the manager to control
            var user = manager.FindByName(name);// find the user by username
                                                //string result = manager.GetRoles(user.Id).ElementAt(0);
            IdentityResult deletionResult;
            if (user.Roles.ToArray()[0].RoleId.Equals("1"))
            {
                deletionResult = manager.RemoveFromRole(user.Id, "Admin");
            }
            else
            {
                deletionResult = manager.RemoveFromRole(user.Id, "Consumer");
            }

            

            return deletionResult;
        }
    }
}
