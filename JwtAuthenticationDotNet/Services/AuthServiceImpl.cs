using JwtAuthenticationDotNet.Data;
using JwtAuthenticationDotNet.Entities;
using JwtAuthenticationDotNet.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthenticationDotNet.Services
{
    public class AuthServiceImpl : IAuthService
    {
        private readonly UserDbContext _context;
        private readonly IConfiguration _configuration;

        public AuthServiceImpl
        (
            UserDbContext context,
            IConfiguration configuration
        )
        {
            _context = context;
            _configuration = configuration;
        }

        public async Task<string?> LoginAsyn(UserDto request)
        {
            var user = _context.Users.FirstOrDefault(u => u.UserName == request.UserName);
            if (user is null)
            {
                return null;
            }

            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
            {
                return null;
            }

            return CreateToken(user); ;
        }

        public async Task<User?> RegisterAsyn(UserDto request)
        {
            // check if the user already exists
            if(await _context.Users.AnyAsync(u => u.UserName == request.UserName))
            {
                return null;
            }

            var user = new User();

            var hasdedPassword = new PasswordHasher<User>().HashPassword(user, request.Password);

            user.UserName = request.UserName;
            user.PasswordHash = hasdedPassword;

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return user;
        }

        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetValue<string>("Jwt:Token")!));
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescriptor = new JwtSecurityToken
            (
                issuer: _configuration.GetValue<string>("Jwt:Issuer"),
                audience: _configuration.GetValue<string>("Jwt:Audience"),
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred
            );

            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }
    }
}
