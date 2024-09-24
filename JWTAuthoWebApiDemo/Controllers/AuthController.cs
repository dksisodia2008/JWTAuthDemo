using JWTAuthoWebApiDemo.Core.DTOs;
using JWTAuthoWebApiDemo.Core.Interfaces;
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
        private readonly IAuthService _authService;
        private readonly IConfiguration _config;
        public AuthController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration config, IAuthService authService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _config = config;
            _authService = authService;
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
            var result = await _authService.RegisterAsync(registordto);

            if (result.IsSucceed)
                return Ok(result);

            return BadRequest(result.ToString());
        }

        [HttpPost]
        [Route("login")]

        public async Task<IActionResult> Login([FromBody] LoginDTO login)
        {
            var result = await _authService.LoginAsync(login);
           
            if (result.IsSucceed)
                return Ok(result);

            return BadRequest(result);
           
        }


        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDTO updatePermission)
        {
            var result = await _authService.MakeAdminAsync(updatePermission);

            if (result.IsSucceed)
                return Ok(result);

            return BadRequest(result);

        }

        public async Task<IActionResult> MakeUser([FromBody] UpdatePermissionDTO updatePermission)
        {
            var result = await _authService.MakeUserAsync(updatePermission);

            if (result.IsSucceed)
                return Ok(result);

            return BadRequest(result);

        }

        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionDTO updatePermission)
        {
            var result = await _authService.MakeAdminAsync(updatePermission);

            if (result.IsSucceed)
                return Ok(result);

            return BadRequest(result);

        }
      

    }
}
