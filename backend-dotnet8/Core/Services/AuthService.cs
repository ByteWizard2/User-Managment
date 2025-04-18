using backend_dotnet8.Core.Constants;
using backend_dotnet8.Core.DbContext;
using backend_dotnet8.Core.Dtos.Auth;
using backend_dotnet8.Core.Dtos.General;
using backend_dotnet8.Core.Entities;
using backend_dotnet8.Core.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace backend_dotnet8.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogService _logService;
        private readonly IConfiguration _configuration;


        public AuthService(UserManager<ApplicationUser> userManager, ILogService logService, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _logService = logService;
            _configuration = configuration;
        }


        public async Task<GeneralServiceResponseDto> SeedRolesAsync()
        {
            bool isOwnerRoleExist = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminRoleExist = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isManagerRoleExist = await _roleManager.RoleExistsAsync(StaticUserRoles.MANAGER);
            bool isUserRoleExist = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);

            if(isOwnerRoleExist && isAdminRoleExist && isManagerRoleExist && isUserRoleExist)
            {
                return new GeneralServiceResponseDto()
                {
                    IsSuccessed = true,
                    StatusCode = 200,
                    Message = "Roles Seeding is  Already Exist"
                };
            }

            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.MANAGER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));

            return new GeneralServiceResponseDto()
            {
                IsSuccessed = true,
                StatusCode = 200,
                Message = "Roles Seeding Done Success"
            };

        }

        public async Task<GeneralServiceResponseDto> RegisterAsync(RegisterDto registerDto)
        {
            var isExistUser = await _userManager.FindByNameAsync(registerDto.UserName);
            if(isExistUser is not null)
            {
                return new GeneralServiceResponseDto()
                {
                    IsSuccessed = false,
                    StatusCode = 400,
                    Message = "UserName Already Exist"
                };
            }

            ApplicationUser newUser = new ApplicationUser()
            {
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName,
                Email = registerDto.Email,
                UserName = registerDto.UserName,
                Address = registerDto.Address,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            var createUserResult = await _userManager.CreateAsync(newUser, registerDto.Password);

            if(!createUserResult.Succeeded)
            {
                var errorString = "User Creation failed because";
                foreach(var error in createUserResult.Errors)
                {
                    errorString += "#" +error.Description;
                }
                return new GeneralServiceResponseDto()
                {
                    IsSuccessed = false,
                    StatusCode = 400,
                    Message = errorString
                };
            }

            //Add default USER role to all users
            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);
            await _logService.SaveNewLog(newUser.UserName, "Registered to Website");

            return new GeneralServiceResponseDto()
            {
                IsSuccessed = true,
                StatusCode = 201,
                Message = "User Created Successfully"
            };
        }

        public async Task<LoginServiceResponseDto> LoginAsync(LoginDto loginDto)
        {
            //Find user with username
            var  user = await _userManager.FindByNameAsync(loginDto.UserName);
            if (user is null)
                return null;

            //Check password of user
            var isPasswordIsCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);
            if (!isPasswordIsCorrect)
                return null;

            //Return Token and userInfo to front-end
            var newToken =await  GenerateJWTTokenAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var userInfo = GenerateUserInfoObject(user,roles);
            await _logService.SaveNewLog(user.UserName, "New Login");

            return new LoginServiceResponseDto()
            {
               NewToken = newToken,
               UserInfo = userInfo
            };
        }

        public async Task<GeneralServiceResponseDto> UpdateRolesAsync(ClaimsPrincipal User, UpdateRoleDto updateRoleDto)
        {
           var user = await _userManager.FindByNameAsync(updateRoleDto.UserName);
            if (user is null)
                return new GeneralServiceResponseDto()
                {
                    IsSuccessed = false,
                    StatusCode = 404,
                    Message = "Invalid UserName"
                };

            var userRoles = await _userManager.GetRolesAsync(user);
            //Just the OWNER and ADMIN can update the roles
            if (User.IsInRole(StaticUserRoles.ADMIN))
            {
                if (updateRoleDto.NewRole == RoleType.USER || updateRoleDto.NewRole == RoleType.MANAGER)
                {
                    //admin can change the role of everyone except  for owners and admins
                    if (userRoles.Any(q => q.Equals(StaticUserRoles.OWNER) || q.Equals(StaticUserRoles.ADMIN)))
                    {
                        return new GeneralServiceResponseDto()
                        {
                            IsSuccessed = false,
                            StatusCode = 403,
                            Message = "You are not allowed to change role of this  user"
                        };
                    }
                    else
                    {
                        await _userManager.RemoveFromRolesAsync(user, userRoles);
                        await _userManager.AddToRoleAsync(user, updateRoleDto.NewRole.ToString());
                        await _logService.SaveNewLog(user.UserName, "User Roles Updated");
                        return new GeneralServiceResponseDto()
                        {
                            IsSuccessed = true,
                            StatusCode = 200,
                            Message = "User Role Updated Successfully"
                        };
                    }

                }
                else return new GeneralServiceResponseDto()
                {
                    IsSuccessed = false,
                    StatusCode = 403,
                    Message = "You are not allowed to change role of this  user"
                };
            }

            else
            {
                // user is owner
                if(userRoles.Any(q=>q.Equals(StaticUserRoles.OWNER)))
                {
                    return new GeneralServiceResponseDto()
                    {
                        IsSuccessed = false,
                        StatusCode = 403,
                        Message = "You are not allowed to change role of this  user"
                    };
                }
                else
                {
                    await _userManager.RemoveFromRolesAsync(user, userRoles);
                    await _userManager.AddToRoleAsync(user, updateRoleDto.NewRole.ToString());
                    await _logService.SaveNewLog(user.UserName, "User Roles Updated");
                    return new GeneralServiceResponseDto()
                    {
                        IsSuccessed = true,
                        StatusCode = 200,
                        Message = "User Role Updated Successfully"
                    };
                }

            }        
           
        }

        public async Task<LoginServiceResponseDto?> MeAsync(MeDto meDto)
        {
           ClaimsPrincipal handler = new JwtSecurityTokenHandler().ValidateToken(meDto.Token, new TokenValidationParameters()
           {
               ValidateIssuer = true,
               ValidateAudience = true,
               ValidIssuer = _configuration["JWT:ValidIssuer"],
               ValidAudience = _configuration["JWT:ValidAudience"],
               IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]))
           }, out SecurityToken securityToken);

            string decodedUserName = handler.Claims.First(q=> q.Type == ClaimTypes.Name).Value;
            if (decodedUserName is null)
                return null;

            var user = await _userManager.FindByNameAsync(decodedUserName);
            if (user is null)
                return null;

            var newToken = await GenerateJWTTokenAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var userInfo = GenerateUserInfoObject(user, roles);
            await _logService.SaveNewLog(user.UserName, "New Token Generated");

            return new LoginServiceResponseDto()
            {
                NewToken = newToken,
                UserInfo = userInfo
            };
        }

        public async Task<IEnumerable<UserInfoResult>> GetUserListAsync()
        {
            var users = await _userManager.Users.ToListAsync();

            List<UserInfoResult> userInfoResults = new List<UserInfoResult>();

            foreach(var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                var userInfo = GenerateUserInfoObject(user, roles);
                userInfoResults.Add(userInfo);
            }
            return userInfoResults;
        }

        public async Task<UserInfoResult?> GetUserDetailsByUserNameAsync(string UserName)
        {
            var user = await _userManager.FindByNameAsync(UserName);
            if (user is null)
                return null;

            var roles = await _userManager.GetRolesAsync(user);
            var userInfo = GenerateUserInfoObject(user, roles);
            return userInfo;
        }

        public async Task<IEnumerable<string>> GetUsernamesListAsync()
        {
            var userName = await _userManager.Users
                .Select(q => q.UserName)
                .ToListAsync();

            return userName;
        }

      

        //GenerateJWTTokenAsync

        private async Task<string> GenerateJWTTokenAsync(ApplicationUser user)
        {

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim("FirstName", user.FirstName),
                new Claim("LastName", user.LastName)

            };
        
          foreach(var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var creds = new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256);
            var tokenObject = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                notBefore:DateTime.Now,
                expires: DateTime.Now.AddHours(3),
                claims:authClaims,
                signingCredentials: creds
            );

            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);
            return token;
        }

        private UserInfoResult GenerateUserInfoObject(ApplicationUser user, IEnumerable<string> Roles)
        {
            return new UserInfoResult()
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                UserName = user.UserName,
                Email = user.Email,
                CreatedAt = user.CreatedAt,
                Roles = Roles
            };
        }
    }
}
