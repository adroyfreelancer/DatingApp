using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using API.Data;
using API.DTOs;
using System.Threading.Tasks;
using API.Entities;
using System.Security.Cryptography;
using System.Linq;
using API.Interfaces;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _context = context;
            _tokenService = tokenService;
        }

        [HttpPost("registerUser")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {
           
           if(await UserExists(registerDto.UserName))
            {
                return BadRequest("username is taken");
            }
            using var hmac = new HMACSHA512();
            var user = new AppUser{
                UserName = registerDto.UserName.ToLower(),
                PasswordHash= hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            
            var userdto = new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
            return userdto;
        }

        public async Task<bool> UserExists(string username)
        {
            return await _context.Users.AnyAsync(x=>x.UserName == username.ToLower());
        }

        [HttpPost("Login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await _context.Users.SingleOrDefaultAsync(x=>x.UserName == loginDto.UserName);
            if(user == null) return Unauthorized("Invalid Username");
            using var hmac= new HMACSHA512(user.PasswordSalt);
            var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(loginDto.Password));
            for(int i=0; i<computedHash.Length;i++)
            {
                if(computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password!");
            }
            var userdto = new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
            return userdto;
        }
    }
}