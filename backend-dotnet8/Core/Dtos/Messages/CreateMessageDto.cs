﻿namespace backend_dotnet8.Core.Dtos.Messages
{
    public class CreateMessageDto
    {
        public string ReceiverUserName { get; set; }
        public string Text { get; set; }
    }
}
