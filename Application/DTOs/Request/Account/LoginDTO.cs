using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Request.Account
{
    public class LoginDTO
    {
        [EmailAddress, Required, DataType(DataType.EmailAddress)]
        [RegularExpression("[^@ \\t\\r\\n]+@[^@ \\t\\r\\n]+\\.[^@ \\t\\r\\n]+",
            ErrorMessage = "email not valid")]
        [DisplayName("Email Address")]
        public string EmailAddress { get; set; } = string.Empty;

        public string Password { get; set; }
    }
}
