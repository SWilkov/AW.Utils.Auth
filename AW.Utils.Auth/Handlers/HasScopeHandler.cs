using AW.Utils.Auth.Requirements;
using Microsoft.AspNetCore.Authorization;
using System.Linq;
using System.Threading.Tasks;

namespace AW.Utils.Auth.Handlers
{
  /// <summary>
  /// Checks User Claims for Scope requirement
  ///
  /// For Asp.net core please setup in Startup.cs as follows
  /// <code>services.AddAuthorization(options =>
  /// <code>var requirement = new HasScopeRequirement("[your:scope]", [your-domain]);</code
  /// <code>options.AddPolicy("[your:scope]", policy => policy.Requirements.Add(requirement));</code>
  /// </summary>
  public class HasScopeHandler : AuthorizationHandler<HasScopeRequirement>
  {
    /// <summary>
    /// Checks User Claims for relevant scope
    /// </summary>
    /// <param name="context"></param>
    /// <param name="requirement"></param>
    /// <returns></returns>
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
      HasScopeRequirement requirement)
    {
      // If user does not have the scope claim, get out of here
      if (!context.User.HasClaim(c => c.Type == "scope" && c.Issuer == requirement.Issuer))
        return Task.CompletedTask;

      // Split the scopes string into an array
      var scopes = context.User.FindFirst(c => c.Type == "scope" && c.Issuer == requirement.Issuer).Value.Split(' ');

      // Succeed if the scope array contains the required scope
      if (scopes.Any(s => s == requirement.Scope))
        context.Succeed(requirement);

      return Task.CompletedTask;
    }
  }
}
