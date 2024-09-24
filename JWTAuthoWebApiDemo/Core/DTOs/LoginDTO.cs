using System.ComponentModel.DataAnnotations;

namespace JWTAuthoWebApiDemo.Core.DTOs
{
    public class LoginDTO
    {
        [Required(ErrorMessage = "UserName is required")]
        public string? UserName { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string? Password { get; set; }
    }
}
