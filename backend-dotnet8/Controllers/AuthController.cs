using backend_dotnet8.Core.Constants;
using backend_dotnet8.Core.Dtos.Auth;
using backend_dotnet8.Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace backend_dotnet8.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        //Route -> Seeds Roles to Db
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var seedResult = await _authService.SeedRolesAsync();
            return StatusCode(seedResult.StatusCode, seedResult.Message);
        }

        //Rout -> Register
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            var registerResult = await _authService.RegisterAsync(registerDto);
            return StatusCode(registerResult.StatusCode, registerResult.Message);
        }

        //Rout -> Login
        [HttpPost]
        [Route("login")]
        public async Task<ActionResult<LoginServiceResponseDto>> Login([FromBody] LoginDto loginDto)
        {
            var loginResult = await _authService.LoginAsync(loginDto);
            if(loginResult is null)
            {
                return Unauthorized("Your Credential are invalid. Please contact to an Admin");
            }

            return Ok(loginResult);
        }

        //Rout -> update user Role
        //An Owner can change everything
        //An Admin can change just User to Manager reverse
        //Manager and User Roles don't have access  to this Route
        [HttpPost]
        [Route("update-role")]
        [Authorize(Roles =StaticUserRoles.OwnerAdmin)]
        public async Task<IActionResult> Updaterole([FromBody]UpdateRoleDto updateRoleDto)
        {
            var updateRoleResult = await _authService.UpdateRolesAsync(User, updateRoleDto);
            if (updateRoleResult.IsSuccessed)
            {
                return Ok(updateRoleResult.Message);
            }
            else
            {
                return StatusCode(updateRoleResult.StatusCode, updateRoleResult.Message);
            }
        }

        //Rout -> getting data of a user form  it's JWT
        [HttpPost]
        [Route("me")]
        public async Task<ActionResult<LoginServiceResponseDto>> Me([FromBody] MeDto token)
        {
            try
            {
                var me = await _authService.MeAsync(token);
                if(me is not null)
                {
                    return Ok(me);
                }
                else
                {
                    return Unauthorized("InvalidToken");
                }

            }
            catch(Exception)
            {
                return Unauthorized("InvalidToken");
            }
        }

        //Rout -> List of all users with details
        [HttpGet]
        [Route("users")]
        public async Task<ActionResult<IEnumerable<UserInfoResult>>> GetUserList()
        {
            var usersList = await _authService.GetUserListAsync();
            return Ok(usersList);
        }

        //Rout -> Get User by UserName
        [HttpGet]
        [Route("users/{userName}")]
        public async Task<ActionResult<UserInfoResult>> GetUserDetailsByUserName([FromRoute] string userName)
        {
            var user = await _authService.GetUserDetailsByUserNameAsync(userName);
            if (user is not null)
            {
                return Ok(user);
            }
            else
            {
                return NotFound("UserName not found");
            }
        }

        //Rout -> Get List of all usernames for  send message
        [HttpGet]
        [Route("usernames")]
        public async Task<ActionResult<IEnumerable<string>>> GetUserNamesList()
        {
            var usernames = await _authService.GetUsernamesListAsync();
            return Ok(usernames);
        }
    }
}
