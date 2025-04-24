//namespace backend_dotnet8.Core.Dtos.Auth
//{
//    public class LoginServiceResponseDto
//    {
//        public string NewToken { get; set; }

//        //this would be returned to frontend
//        public UserInfoResult UserInfo { get; set; }
//    }
//}



namespace backend_dotnet8.Core.Dtos.Auth
{
    public class LoginServiceResponseDto
    {
        public string NewToken { get; set; }

        // This would be returned to front-end
        public UserInfoResult UserInfo { get; set; }
    }
}

