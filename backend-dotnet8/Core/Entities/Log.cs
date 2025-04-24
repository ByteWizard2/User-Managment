//namespace backend_dotnet8.Core.Entities
//{
//    public class Log:BaseEntities<int>
//    {
//        public string? UserName { get; set; }
//        public string Description { get; set; }
//    }
//}

namespace backend_dotnet8.Core.Entities
{
    public class Log : BaseEntity<int>
    {
        public string? UserName { get; set; }
        public string Description { get; set; }
    }
}

