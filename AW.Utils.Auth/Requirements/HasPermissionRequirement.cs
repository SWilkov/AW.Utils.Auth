using Microsoft.AspNetCore.Authorization;
using System;

namespace AW.Utils.Auth.Requirements
{
  public class HasPermissionRequirement : IAuthorizationRequirement
  {
    /// <summary>
    /// The Permssion name ie read:invoices
    /// </summary>
    public string Permission { get; }
    /// <summary>
    /// The Issuer of the permission ie a domain
    /// </summary>
    public string Issuer { get; }

    public HasPermissionRequirement(string permission, string issuer)
    {
      this.Permission = permission ?? throw new ArgumentNullException(nameof(permission));
      this.Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
    }
  }
}
