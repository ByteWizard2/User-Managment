//namespace backend_dotnet8.Core.Entities
//{
//    public class Message:BaseEntities<long>
//    {
//        public string SenderUserName { get; set; }
//        public string ReceiverUserName { get; set; }
//        public string Text { get; set; }
//    }
//}

using backend_dotnet8.Core.Entities;

namespace backend_dotnet8.Core.Entities
{
    public class Message : BaseEntity<long>
    {
        public string SenderUserName { get; set; }
        public string ReceiverUserName { get; set; }
        public string Text { get; set; }
    }
}


