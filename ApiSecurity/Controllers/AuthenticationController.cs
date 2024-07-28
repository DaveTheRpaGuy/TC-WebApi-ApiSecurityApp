using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ApiSecurity.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly IConfiguration _config;

    public AuthenticationController(IConfiguration config)
    {
        _config = config;
    }

    // Equivalent to creating a class with two properties
    // Note that the capitalization doesn't break because when the params are grabbed from the body...
    // it'll know to be case insensitive or maybe it just looks for userName and password, but either way same difference
    public record AuthenticationData(string? UserName, string? Password);
    public record UserData(int UserId, string UserName);

    // api/Authentication/token
    [HttpPost("token")]
    public ActionResult<string> Authenticate([FromBody] AuthenticationData data)
    {
        var user = ValidateCredentials(data);

        if (user is null) return Unauthorized();

        string token = GenerateToken(user);

        return Ok(token);
    }

    private string GenerateToken(UserData user)
    {
        var secretKey = new SymmetricSecurityKey(
            Encoding.ASCII.GetBytes(
                _config.GetValue<string>("Authentication:SecretKey")));

        var signingCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

        List<Claim> claims = new();
        claims.Add(new(JwtRegisteredClaimNames.Sub, user.UserId.ToString()));
        claims.Add(new(JwtRegisteredClaimNames.UniqueName, user.UserName));

        var token = new JwtSecurityToken(
            _config.GetValue<string>("Authentication:Issuer"),
            _config.GetValue<string>("Authentication:Audience"),
            claims,
            DateTime.UtcNow, // when this token becomes valid
            DateTime.UtcNow.AddMinutes(1), // when this token expires (set low for testing)
            signingCredentials
            );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private UserData ValidateCredentials(AuthenticationData data)
    {
        // FOR THIS METHOD, THIS IS ONLY A DEMO - DO NOT USE IN PRODUCTION OR REAL LIFE
        // THIS IS WHERE YOU'D CALL THE AUTHENTICATION SYSTEM THAT YOU USE, SUCH AS AUTH0 OR WHATEVER
        if (CompareValues(data.UserName, "dmorris")
            && CompareValues(data.Password, "Test123"))
        {
            return new UserData(1, data.UserName!);
        }

        if (CompareValues(data.UserName, "sstorm")
            && CompareValues(data.Password, "Test123"))
        {
            return new UserData(2, data.UserName!);
        }

        return null;
    }

    private bool CompareValues(string? actual, string expected)
    {

        if (actual is null) return false;

        if (actual.Equals(expected))
        {
            return true;
        }

        return false;
    }
}
