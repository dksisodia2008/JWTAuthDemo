using JWTAuthoWebApiDemo.Core.DTOs;
using JWTAuthoWebApiDemo.Core.Interfaces;
using JWTAuthoWebApiDemo.Core.OtherObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthoWebApiDemo.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _config;

        public AuthService(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration config)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _config = config;
        }
        public async Task<AuthServiceResponseDto> LoginAsync(LoginDTO loginDTO)
        {
            var user = await _userManager.FindByNameAsync(loginDTO.UserName);
            if (user == null)

                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "Invalid Credentials"
                };

            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDTO.Password);

            if (!isPasswordCorrect)

                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "Invalid Credentials"
                };
                    
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

             return new AuthServiceResponseDto()
            {
                IsSucceed = false,
                Message = token
             };

        }

        public async Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDTO updatePermissionDTO)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDTO.UserName);
            if (user is null)
            {
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "User already exist!!"
                };
            }
            await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "User is now an Admin"
            }; 
        }

        public async Task<AuthServiceResponseDto> MakeOwnerAsync(UpdatePermissionDTO updatePermissionDTO)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDTO.UserName);
            if (user is null)
            {
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "Invalid User Name!!"
                };
            }
            await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "User is now an Owner"
            };
        }

        public Task<AuthServiceResponseDto> MakeUserAsync(UpdatePermissionDTO updatePermissionDTO)
        {
            throw new NotImplementedException();
        }

        public async Task<AuthServiceResponseDto> RegisterAsync(RegisterDTO registerDTO)
        {
            var isExitsUser = await _userManager.FindByNameAsync(registerDTO.UserName);
            if (isExitsUser != null)

                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "UserName already Exists"
                };
                    
            IdentityUser newUser = new IdentityUser()
            {
                Email = registerDTO.Email,
                UserName = registerDTO.UserName,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            var createUserResult = await _userManager.CreateAsync(newUser, registerDTO.Password);

            if (!createUserResult.Succeeded)
            {
                var errorString = "User creation Failed Because:";
                foreach (var error in createUserResult.Errors)
                {
                    errorString += " # " + error.Description;
                }
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = errorString
                };
            }

            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "User created Successfully"
            };

        }

        public async Task<AuthServiceResponseDto> SeedRolesAsync()
        {
            bool isOwnerRoleExits = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isUserRoleExits = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);
            bool isAdminRoleExits = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);

            if (isUserRoleExits && isAdminRoleExits && isOwnerRoleExits)

                return new AuthServiceResponseDto()
                {
                    IsSucceed = true,
                    Message = "Role seeding is already done"
                };

            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "Role seeding done Successfully"
            };

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
