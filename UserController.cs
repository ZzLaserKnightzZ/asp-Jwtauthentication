using auth.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace auth.controller
{
    public class UserController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly AppDbContext _dbContext;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IOptions<AppSettings> _appsetings;
        public UserController (UserManager<IdentityUser> userManager,
                                AppDbContext appDbContext,
                                SignInManager<IdentityUser> signInManager,
                                IOptions<AppSettings> appsetings)
        {
            _userManager = userManager;
            _dbContext = appDbContext;
            _signInManager = signInManager;
            _appsetings = appsetings;
        }

        [HttpPost("Auth")]
        public async Task<IActionResult> Auth([FromBody]ModelUser user)
        {
            var resault = await _signInManager.PasswordSignInAsync(user.username, user.passsword, false, false);
            if (resault.Succeeded) {
                var tokenhandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_appsetings.Value.Secret);

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                    {
                    new Claim( ClaimTypes.UserData,"IsValid", ClaimValueTypes.String, "(local)" )
                    }),
                    Issuer = "self",
                    Audience = "https://www.mywebsite.com",
                    Expires = DateTime.Now.AddDays(12),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256),
                };

                var token = tokenhandler.CreateToken(tokenDescriptor);

                return Json(new
                {
                    username = user.username,
                    token = tokenhandler.WriteToken(token)
                });
            }
            return NotFound();
        }

        [HttpGet("crateuser")]
        public async Task<IActionResult> TestCreateUser()
        {
            var resault = await _userManager.CreateAsync(new IdentityUser {
                Email = "a.a@g.com", 
                UserName = "anupong"},
                "dfg656ERTyRRYt6r66tr9");

            if (resault.Succeeded) {
                return Ok(new {data = "ok" });
            }
            else
            {
                return BadRequest();
            }
            
        }

        [HttpGet("test")]
        public IActionResult testverify(AuthToken authToken)
        {
            if(ValidateJwtToken(authToken.Token) != null)
            {
                return Json(new { Ok = "ok" });
            }
            return Json(new { Ok = "fail" });
        }
        public int? ValidateJwtToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_appsetings.Value.Secret);
            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var accountId = int.Parse(jwtToken.Claims.First(x => x.Type == "id").Value);

                // return account id from JWT token if validation successful
                return accountId;
            }
            catch
            {
                // return null if validation fails
                return null;
            }
        }
    }

    public class ModelUser
    {
        public string username { get; set; }
        public string passsword { get; set; }
    }

    public class AuthToken
    {
        public string username { get; set; }
        public string Token { get; set; }
    }

}
