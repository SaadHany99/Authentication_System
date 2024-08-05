using System.ComponentModel.DataAnnotations;

namespace UserAuthenticationSystem.Models
{
    public class Register
    {
        [MinLength(5,ErrorMessage ="User Name must be at Least 5 Characters")]
        public string Email { get; set; }
        public string Password { get; set; }
        public string PhoneNumber { get; set; }
    }
}
