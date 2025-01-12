using JwtAuthenticationDotNet.Entities;
using JwtAuthenticationDotNet.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuthenticationDotNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new();

        private readonly IConfiguration _configuration;

        public AuthController
        (
            IConfiguration configuration
        )
        {
            _configuration = configuration;
        }

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

            var token = CreateToken(user);

            return Ok(token);
        }

        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetValue<string>("AppSettings:Token")!));
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescriptor = new JwtSecurityToken
            (
                issuer: _configuration.GetValue<string>("AppSettings:Issuer"),
                audience: _configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred
            );

            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }
    }
}
