using JwtAuthenticationDotNet.Entities;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthenticationDotNet.Data
{
    public class UserDbContext(DbContextOptions<UserDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users { get; set; }
    }
}
