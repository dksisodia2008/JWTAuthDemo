using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthoWebApiDemo.Core.DBContext
{
    public class ApplicationDBContext : IdentityDbContext
    {
      
        public ApplicationDBContext(DbContextOptions<ApplicationDBContext> options) : base(options) 
        {
        
        }
    }
}
