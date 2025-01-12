using JwtAuthenticationDotNet.Entities;
using JwtAuthenticationDotNet.Models;

namespace JwtAuthenticationDotNet.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsyn(UserDto request);
        Task<string?> LoginAsyn(UserDto request);
    }
}
