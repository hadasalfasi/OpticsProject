using DAL.Dtos;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace OpticsProject.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly string _secretKey;
        private readonly string _issuer;
        private readonly string _audience;

        public AuthController(IConfiguration configuration)
        {
            _secretKey = configuration["Jwt:Key"];
            _issuer = configuration["Jwt:Issuer"];
            _audience = configuration["Jwt:Audience"];
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginDto login)
        {
           if (login.Username == "test" && login.Password == "password") 
            {
              var token = GenerateToken(login.Username, "Admin"); 
              return Ok(new { Token = token });
            }

            return Unauthorized("Invalid credentials");
        }

        private string GenerateToken(string userId,string role)
        {
            if (string.IsNullOrEmpty(_secretKey) || _secretKey.Length < 16)
            {
                throw new ArgumentException("Invalid secret key. The key must be at least 16 characters long.");
            }

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Role, role)

            };

            var token = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30), 
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
