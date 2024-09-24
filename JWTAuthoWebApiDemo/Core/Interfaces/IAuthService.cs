using JWTAuthoWebApiDemo.Core.DTOs;
using Microsoft.AspNetCore.Authorization;

namespace JWTAuthoWebApiDemo.Core.Interfaces
{
    public interface IAuthService
    {
        Task<AuthServiceResponseDto> SeedRolesAsync();
        Task<AuthServiceResponseDto> RegisterAsync(RegisterDTO registerDTO);
        Task<AuthServiceResponseDto> LoginAsync(LoginDTO loginDTO);
        Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDTO updatePermissionDTO);
        Task<AuthServiceResponseDto> MakeUserAsync(UpdatePermissionDTO updatePermissionDTO);

        Task<AuthServiceResponseDto> MakeOwnerAsync(UpdatePermissionDTO updatePermissionDTO);


    }
}
