namespace JwtAuthenticationDotNet.Models
{
    public class RefreshTokenRequestDto
    {
        public Guid userId { get; set; }
        public required string RefreshToken { get; set; }
    }
}
