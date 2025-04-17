using backend_dotnet8.Core.Dtos.Auth;
using backend_dotnet8.Core.Dtos.General;
using System.Security.Claims;

namespace backend_dotnet8.Core.Interfaces
{
    public interface IAuthService
    {
        Task<GeneralServiceResponseDto> SeedRolesAsync();
        Task<GeneralServiceResponseDto> RegisterAsync(RegisterDto registerDto);
        Task<LoginServiceResponseDto?> LoginAsync(LoginDto loginDto);
        Task<GeneralServiceResponseDto> UpdateRolesAsync(ClaimsPrincipal User, UpdateRoleDto updateRoleDto);
        Task<LoginServiceResponseDto?> MeAsync(MeDto meDto);
        Task<IEnumerable<UserInfoResult>> GetUserListAsync();
        Task<UserInfoResult?> GetUserDetailsByUserNameAsync(string UserName);
        Task<IEnumerable<string>> GetUsernamesListAsync();


    }
}
