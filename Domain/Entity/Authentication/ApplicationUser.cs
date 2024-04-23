using Microsoft.AspNetCore.Identity;

namespace Domain.Entity.Authentication
{
    public class ApplicationUser : IdentityUser
    {
        public string? Name { get; set; }
    }
}
