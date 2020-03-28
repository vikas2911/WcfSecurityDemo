using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.IdentityModel.Claims;

namespace WcfSecurity.SecurityPolicy
{
    class ClaimsUtil
    {
        const string CLAIM_FORMAT_STRING = "{0, -5} {1, -15} {2}";
        private StringBuilder claimsText;
        TextWriter twClaims;

        public ClaimsUtil(TextWriter tw)
        {
            claimsText = new StringBuilder();
            twClaims = tw;
        }

        public void displayClaimSet(ClaimSet cs)
        {
            claimsText.AppendLine(string.Format(CLAIM_FORMAT_STRING, "RIGHT", "CLAIM_TYPE", "RESOURCE"));

            // display claims for subject of this claimset
            foreach (Claim c in cs)
            {
                displayClaim(c);
            }

            claimsText.AppendLine("ISSUED BY: ");

            // display claims for issuer of this claimset
            if (null == cs.Issuer)
            {
                claimsText.AppendLine("null");
            }
            else if (object.ReferenceEquals(cs, cs.Issuer))
            {
                // self-asserted claims (issuer is the same as subject)
                claimsText.AppendLine("self");
            }
            else
            {
                displayClaimSet(cs.Issuer);
            }

            twClaims.Write(claimsText.ToString());
        }

        // print a compact display of the supplied claim
        private void displayClaim(Claim c)
        {
            string right;
            if (c.Right.Equals(Rights.Identity))
            {
                right = "ID";
            }
            else if (c.Right.Equals(Rights.PossessProperty))
            {
                right = "PP";
            }
            else right = c.Right;

            // make things a little more readable
            string claimType = c.ClaimType.Replace("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/", ".../");
            string value = stringizeResource(c.Resource);

            claimsText.AppendLine(string.Format(CLAIM_FORMAT_STRING, right, claimType, value));
        }

        private string stringizeResource(object resource)
        {
            // sometimes the claim's value will simply be a string
            string stringResource = resource as string;
            if (null != stringResource) return stringResource + " (string)";

            SecurityIdentifier sid = resource as SecurityIdentifier;
            if (null != sid) return getAccountName(sid) + " (SecurityIdentifier)";

            X500DistinguishedName dn = resource as X500DistinguishedName;
            if (null != dn) return dn.Name + " (X500DistinguishedName)";

            RSACryptoServiceProvider key = resource as RSACryptoServiceProvider;
            if (null != key) return string.Format("{0} bit RSA public key (RSACryptoServiceProvider)", key.KeySize);

            // for anything else, just display the type name
            return string.Format("({0})", resource.GetType().Name);
        }

        private string getAccountName(SecurityIdentifier sid)
        {
            try
            {
                return sid.Translate(typeof(NTAccount)).ToString();
            }
            catch (IdentityNotMappedException)
            {
                return sid.Value;
            }
        }
    }
}
