# XafSecurityHelper
The actual DX components version - 15.2.5


If you need add new [MemberAccessPermission and/or TypePermission](https://documentation.devexpress.com/#eXpressAppFramework/DevExpressExpressAppSecurityStrategySecuritySystemRoleMembersTopicAll) for entity use the following syntax : 

```
var role = objectSpace.CreateObject<SomeObject>();

role.AddMemberAccessPermissionFluent<SomeEntity>(SecurityOperationsFluentExtension.Create)
  .AddTypePermissionFluent<SomeEntity>(SecurityOperationsFluentExtension.Create);
  
role.Save();
```
