using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace AspJwtDemo
{
    public class JwtTokenHelper : ITokenHelper
    {
        private const string Secret = "supersecret_that_should_be_stored_in_a_secret_manager";
        private static readonly TimeSpan TokenLifetime = TimeSpan.FromMinutes(30);

        public string GetToken(TokenGenerationRequest request)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(Secret);

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, request.Email),
                new(JwtRegisteredClaimNames.Email, request.Email),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new("userId", request.Id),
            };

            // parse from JSON to claims
            foreach (var claimPair in request.CustomClaims)
            {
                var jsonElement = (JsonElement)claimPair.Value;
                var valueType = jsonElement.ValueKind switch
                {
                    JsonValueKind.Number => ClaimValueTypes.Integer,
                    JsonValueKind.True => ClaimValueTypes.Boolean,
                    JsonValueKind.False => ClaimValueTypes.Boolean,
                    _ => ClaimValueTypes.String
                };

                claims.Add(new Claim(claimPair.Key, jsonElement.ToString(), valueType));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.Add(TokenLifetime),
                Issuer = "http://localhost:5000",
                Audience = "http://localhost:5000",
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }


    }

    public class TokenGenerationRequest
    {
        public string Id { get; init; }
        public string Email { get; init; }
        public Dictionary<string, object> CustomClaims { get; init; }
    }

    public interface ITokenHelper
    {
        public string GetToken(TokenGenerationRequest request);
    }
}
