using AW.Utils.Auth.Requirements;
using Microsoft.AspNetCore.Authorization;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace AW.Utils.Auth.Handlers
{
  /// <summary>
  /// Checks User Claims for Permission requirement
  ///
  /// For Asp.net core please setup in Startup.cs as follows
  /// <code>services.AddAuthorization(options =>
  /// <code>var requirement = new HasPermissionRequirement("[your:permission]", [your-domain]);</code
  /// <code>options.AddPolicy("[your:permission]", policy => policy.Requirements.Add(requirement));</code>
  /// </summary>
  public class HasPermissionHandler : AuthorizationHandler<HasPermissionRequirement>
  {
    /// <summary>
    /// Checks User Claims for relevant permissions. 
    /// </summary>
    /// <param name="context"></param>
    /// <param name="requirement"></param>
    /// <returns></returns>
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
      HasPermissionRequirement requirement)
    {
      if (context == null)
        throw new ArgumentNullException(nameof(context));

      if (!context.User.HasClaim(c => c.Type == "permissions" && c.Issuer == requirement.Issuer))
        return Task.CompletedTask;

      var permissions = context.User.FindAll(c => c.Type == "permissions" && c.Issuer == requirement.Issuer);
      //No permissions found carry on
      if (permissions == null || !permissions.Any())
        return Task.CompletedTask;

      //Requirement is successfully evaluated
      if (permissions.Any(p => p.Value == requirement.Permission && p.Issuer == requirement.Issuer))
        context.Succeed(requirement);

      return Task.CompletedTask;
    }
  }
}
