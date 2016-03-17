using System;
using System.ComponentModel;
using System.Reflection;
using System.Collections.Generic;
using System.Linq;
using DevExpress.Data.Filtering;
using DevExpress.ExpressApp;
using DevExpress.ExpressApp.Security.Strategy;



namespace XafSecurityHelper
{
    public static class SecurityPermissionsFluent
    {

        #region FluentMethods
        private static string GetDescriptionAttribute(Enum value)
        {

            FieldInfo fi = value.GetType().GetField(value.ToString());
            DescriptionAttribute[] attributes = (DescriptionAttribute[])fi.GetCustomAttributes(typeof(DescriptionAttribute), false);
            if (attributes.Length > 0)
            {
                return attributes[0].Description;
            }
            else
            {
                throw new ArgumentException(String.Format("DescriptionAttribute not specified for SecurityOperationsEnum {0} value", value.ToString()));
            }
        }

        private static List<Type> GetListTypesFromInterface(Type typeForInterfaces, Type typeForAssembly)
        {
            return Assembly.GetAssembly(typeForAssembly)
              .GetExportedTypes()
              .Where(t => t.IsClass && t.GetInterface(typeForInterfaces.FullName) != null)
              .ToList();
        }

        public static SecuritySystemRole AddTypePermissionFluent<T>(this SecuritySystemRole securityRole, SecurityOperationsFluentExtension securityOperation)
        {
            if (typeof(T).IsInterface)
            {
                foreach (var type in GetListTypesFromInterface(typeof(T), securityRole.GetType()))
                    securityRole.SetTypePermissions(type, GetDescriptionAttribute(securityOperation), DevExpress.ExpressApp.Security.Strategy.SecuritySystemModifier.Allow);

                return securityRole;
            }

            securityRole.SetTypePermissions<T>(GetDescriptionAttribute(securityOperation), SecuritySystemModifier.Allow);
            return securityRole;
        }

        public static SecuritySystemRole AddTypePermissionFluent(this SecuritySystemRole securityRole, List<Type> typeList, SecurityOperationsFluentExtension securityOperation)
        {

            foreach (var type in typeList)
            {
                if (type.IsInterface)
                {
                    foreach (var classType in GetListTypesFromInterface(type, securityRole.GetType()))
                        securityRole.SetTypePermissions(classType, GetDescriptionAttribute(securityOperation), SecuritySystemModifier.Allow);
                    continue;
                }
                securityRole.SetTypePermissions(type, GetDescriptionAttribute(securityOperation), SecuritySystemModifier.Allow);
            }
            return securityRole;
        }

        public static SecuritySystemRole AddMemberAccessPermissionFluent<T>(this SecuritySystemRole securityRole, string members, SecurityOperationsFluentExtension securityOperation, string criteria = null)
        {

            if (String.IsNullOrEmpty(members))
                throw new ArgumentNullException(String.Format("Members arguments (Role {0} Type {1} ) is null or empty", securityRole.Name, typeof(T).FullName));

            if (typeof(T).IsInterface)
            {
                foreach (var type in GetListTypesFromInterface(typeof(T), securityRole.GetType()))
                {
                    if (String.IsNullOrEmpty(criteria))
                        securityRole.AddMemberAccessPermission(type, members, GetDescriptionAttribute(securityOperation));
                    else
                        securityRole.AddMemberAccessPermission(type, members, GetDescriptionAttribute(securityOperation), criteria);
                }

                return securityRole;
            }

            if (String.IsNullOrEmpty(criteria))
                securityRole.AddMemberAccessPermission<T>(members, GetDescriptionAttribute(securityOperation));
            else
                securityRole.AddMemberAccessPermission<T>(members, GetDescriptionAttribute(securityOperation), criteria);

            return securityRole;
        }

        public static SecuritySystemRole AddMemberAccessPermissionFluent(this SecuritySystemRole securityRole, List<Type> typeList, string members, SecurityOperationsFluentExtension securityOperation, string criteria = null)
        {

            if (String.IsNullOrEmpty(members))
                throw new ArgumentNullException(String.Format("Members arguments (EmployeeRole {0} list types ) is null or empty", securityRole.Name));

            foreach (var type in typeList)
            {
                if (type.IsInterface)
                {
                    foreach (var classType in GetListTypesFromInterface(type, securityRole.GetType()))
                    {
                        if (String.IsNullOrEmpty(criteria))
                            securityRole.AddMemberAccessPermission(classType, members, GetDescriptionAttribute(securityOperation));
                        else
                            securityRole.AddMemberAccessPermission(classType, members, GetDescriptionAttribute(securityOperation), criteria);
                    }
                    continue;
                }

                if (String.IsNullOrEmpty(criteria))
                    securityRole.AddMemberAccessPermission(type, members, GetDescriptionAttribute(securityOperation));
                else
                    securityRole.AddMemberAccessPermission(type, members, GetDescriptionAttribute(securityOperation), criteria);
            }

            return securityRole;
        }
        public static SecuritySystemRole AddObjectAccessPermissionFluent<T>(this SecuritySystemRole securityRole, SecurityOperationsFluentExtension securityOperation, string criteria)
        {

            if (String.IsNullOrEmpty(criteria))
                throw new ArgumentNullException("SecurityOperations or criteria arguments is null or empty");

            if (typeof(T).IsInterface)
            {
                foreach (var type in GetListTypesFromInterface(typeof(T), securityRole.GetType()))
                    securityRole.AddObjectAccessPermission(type, criteria, GetDescriptionAttribute(securityOperation));

                return securityRole;
            }

            securityRole.AddObjectAccessPermission<T>(criteria, GetDescriptionAttribute(securityOperation));
            return securityRole;
        }
        #endregion
    }

    public enum SecurityOperationsFluentExtension
    {
        [DescriptionAttribute("Create")]
        Create,
        [DescriptionAttribute("Create;Read;Write;Delete")]
        CRUDAccess,
        [DescriptionAttribute("Delete")]
        Delete,
        [DescriptionAttribute("Read;Write;Delete;Navigate;Create")]
        FullAccess,
        [DescriptionAttribute("Read;Write;Delete;Navigate")]
        FullObjectAccess,
        [DescriptionAttribute("Navigate")]
        Navigate,
        [DescriptionAttribute("Read")]
        Read,
        [DescriptionAttribute("Read;Navigate")]
        ReadOnlyAccess,
        [DescriptionAttribute("Read;Write")]
        ReadWriteAccess,
        [DescriptionAttribute("Read;Write;Navigate")]
        ReadWriteNavigate,
        [DescriptionAttribute("Write")]
        Write,
        [DescriptionAttribute("Write;Create;Delete;Navigate")]
        WriteCreateDeleteNavigate,
        [DescriptionAttribute("Write;Create")]
        WriteCreate,
        [DescriptionAttribute("Write;Create;Delete")]
        WriteCreateDelete,
        [DescriptionAttribute("Write;Create;Navigate")]
        WriteCreateNavigate,
        [DescriptionAttribute("Write;Create;Read;Navigate")]
        WriteCreateReadNavigate
    }

}