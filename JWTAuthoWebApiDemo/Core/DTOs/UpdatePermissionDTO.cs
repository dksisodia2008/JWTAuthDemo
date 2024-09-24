using System.ComponentModel.DataAnnotations;

namespace JWTAuthoWebApiDemo.Core.DTOs
{
    public class UpdatePermissionDTO
    {

        [Required(ErrorMessage = "UserName is required")]
        public string? UserName { get; set; }

    }
}
