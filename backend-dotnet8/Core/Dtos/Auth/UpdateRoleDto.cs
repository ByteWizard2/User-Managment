﻿//using System.ComponentModel.DataAnnotations;

//namespace backend_dotnet8.Core.Dtos.Auth
//{
//    public class UpdateRoleDto
//    {
//        [Required(ErrorMessage = "Role is required.")]
//        public string UserName { get; set; }
//        public RoleType NewRole { get; set; }

//    }

//    public enum RoleType
//    {
//        ADMIN,
//        MANAGER,
//        USER
//    }
//}


using System.ComponentModel.DataAnnotations;

namespace backend_dotnet8.Core.Dtos.Auth
{
    public class UpdateRoleDto
    {
        [Required(ErrorMessage = " UserName is required")]
        public string UserName { get; set; }
        public RoleType NewRole { get; set; }

    }

    public enum RoleType
    {
        ADMIN,
        MANAGER,
        USER
    }
}

