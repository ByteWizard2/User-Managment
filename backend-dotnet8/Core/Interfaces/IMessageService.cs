using backend_dotnet8.Core.Dtos.General;
using backend_dotnet8.Core.Dtos.Messages;
using System.Security.Claims;
using System.Threading.Tasks;

namespace backend_dotnet8.Core.Interfaces
{
    public interface IMessageService
    {
        Task<GeneralServiceResponseDto> CreateNewMessageAsync(ClaimsPrincipal user, CreateMessageDto createMessageDto);
        Task <IEnumerable<GetMessageDto>> GetMessagesAsync();
        Task<IEnumerable<GetMessageDto>> GetMyMessagesAsync(ClaimsPrincipal User);

    }
}
