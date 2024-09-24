using JWTAuthoWebApiDemo.Core.DTOs;
using JWTAuthoWebApiDemo.Core.OtherObjects;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Writers;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Text;

namespace JWTAuthoWebApiDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _config;
        public AuthController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration config)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _config = config;
        }

        // Role for seeding my roles to DB
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            bool isOwnerRoleExits = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isUserRoleExits = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);
            bool isAdminRoleExits = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);

            if (isUserRoleExits && isAdminRoleExits && isOwnerRoleExits)
                return Ok("Role seeding is already done");

            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            
            return Ok("Role seeding done Successfully");
            
        }

        // Role for seeding my roles to DB
        [HttpPost]
        [Route("register")]

        public async Task<IActionResult> Register([FromBody] RegisterDTO registordto)
        {
            var isExitsUser = await _userManager.FindByNameAsync(registordto.UserName);
            if (isExitsUser !=null)
            
                return BadRequest("UserName already Exists");

            IdentityUser newUser = new IdentityUser()
            {
                Email = registordto.Email,
                UserName = registordto.UserName,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            var createUserResult = await _userManager.CreateAsync(newUser, registordto.Password);

           if(!createUserResult.Succeeded)
            {
                var errorString = "User creation Failed Because:";
                foreach (var error in createUserResult.Errors)
                {
                    errorString += " # " + error.Description;
                }
                return BadRequest(errorString);
            }

            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            return Ok("User created Successfully");
        }

        [HttpPost]
        [Route("login")]

        public async Task<IActionResult> Login([FromBody] LoginDTO login)
        {
            var user = await _userManager.FindByNameAsync(login.UserName);
            if (user == null)
                return Unauthorized("Invalid Credentials");

            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, login.Password);

            if (!isPasswordCorrect)
                return Unauthorized("Invalid Credentials ");

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("JWTID", Guid.NewGuid().ToString()),
            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }
            var token = GenerateNewjsonWebToken(authClaims);

            return Ok(token);
        }


        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDTO updatePermission)
        {
            var user = await _userManager.FindByNameAsync(updatePermission.UserName);
            if (user is null)
            {
                return BadRequest("Invalid User Name!!");
            }
            await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);

            return Ok("User is now an Owner");
            
        }

        public async Task<IActionResult> MakeUser([FromBody] UpdatePermissionDTO updatePermission)
        {
            var user = await _userManager.FindByNameAsync(updatePermission.UserName);
            if (user is null)
            {
                return BadRequest("Invalid User Name!!");
            }
            await _userManager.AddToRoleAsync(user, StaticUserRoles.USER);

            return Ok("User is now an User");

        }

        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionDTO updatePermission)
        {
            var user = await _userManager.FindByNameAsync(updatePermission.UserName);
            if (user is null)
            {
                return BadRequest("Invalid User Name!!");
            }
            await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);

            return Ok("User is now an Admin");

        }
        private string GenerateNewjsonWebToken(List<Claim> claims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:Secret"]));

            var tokenObject = new JwtSecurityToken(
                 issuer: _config["JWT:ValidIssuer"],
                 audience: _config["JWT:ValidAudience"],
                 expires: DateTime.Now.AddHours(1),
                 claims: claims,
                 signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
                ); 

            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);

            return token;

        }

    }
}
