using JwtAuthenticationDotNet.Entities;
using JwtAuthenticationDotNet.Models;

namespace JwtAuthenticationDotNet.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsyn(UserDto request);
        Task<TokenResponseDto?> LoginAsyn(UserDto request);
        Task<TokenResponseDto?> RefreshToken(RefreshTokenRequestDto request);
    }
}
