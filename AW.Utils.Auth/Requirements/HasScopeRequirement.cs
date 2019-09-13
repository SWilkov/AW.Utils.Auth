using Microsoft.AspNetCore.Authorization;
using System;

namespace AW.Utils.Auth.Requirements
{
  public class HasScopeRequirement : IAuthorizationRequirement
  {
    /// <summary>
    /// The Scope name ie openid
    /// </summary>
    public string Scope { get; }
    /// <summary>
    /// The Issuer of the permission ie a domain
    /// </summary>
    public string Issuer { get; }
    public HasScopeRequirement(string scope, string issuer)
    {
      this.Scope = scope ?? throw new ArgumentNullException(nameof(scope));
      this.Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
    }
  }
}
