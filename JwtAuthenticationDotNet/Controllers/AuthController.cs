using JwtAuthenticationDotNet.Entities;
using JwtAuthenticationDotNet.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthenticationDotNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new();

        [HttpPost("register")]
        public IActionResult Register(UserDtop request)
        {
            var hasdedPassword = new PasswordHasher<User>().HashPassword(user, request.Password);

            user.UserName = request.UserName;
            user.PasswordHash = hasdedPassword;
            return Ok(user);
        }

        [HttpPost("login")]
        public IActionResult Login(UserDtop request)
        {
            if(user.UserName != request.UserName)
            {
                return BadRequest("User Not Found");
            }

            if(new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
            {
                return BadRequest("Invalid password");
            }

            var token = "success";

            return Ok(token);
        }
    }
}
