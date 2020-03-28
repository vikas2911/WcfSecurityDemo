using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Xml.XPath;
using System.IO;
using System.IdentityModel.Claims;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.IdentityModel.Policy;
using System.Text;
using System.Xml;
using System.Threading;

namespace WcfSecurity.SecurityPolicy
{
    class AuthorizationManager : ServiceAuthorizationManager 
    {
        const string CLAIM_FORMAT_STRING = "{0, -5} {1, -15} {2}";
        private StringBuilder claimsText; 

        public override bool CheckAccess(OperationContext operationContext, ref Message message)
        {
            claimsText = new StringBuilder(); 

            base.CheckAccess(operationContext, ref message);
            string action = operationContext.IncomingMessageHeaders.Action;

            TextWriter twClaims = File.AppendText(@"c:\Servicelogs\Claims.logs");

            AuthorizationContext actx = operationContext.ServiceSecurityContext.AuthorizationContext;
            foreach (ClaimSet cs in actx.ClaimSets)
            {
                claimsText.AppendLine("------------------------------");
                displayClaimSet(cs);
            }
            twClaims.WriteLine("Action:" + action); 
            twClaims.Write(claimsText.ToString());
            twClaims.Close();

            // Iterate through the various claimsets in the authorizationcontext
            foreach (ClaimSet cs in operationContext.ServiceSecurityContext.AuthorizationContext.ClaimSets)
            {
                // Only look at claimsets issued by System.
                //if (cs.Issuer == ClaimSet.System)
                {
                    // Iterate through claims of type "http://example.org/claims/allowedoperation"
                    foreach (Claim c in cs.FindClaims("http://example.org/claims/allowedoperation", Rights.PossessProperty))
                    {
                        // If the Claim resource matches the action URI then return true to allow access
                        if (action == c.Resource.ToString())
                            return true;
                    }
                }
            }

            return false;
        }
      // rest omitted

        private IPrincipal GetPrincipal(OperationContext operationContext)
        {
            return Thread.CurrentPrincipal;
        }

        public class StandardNamespaceManager : XmlNamespaceManager
    {
        public StandardNamespaceManager(XmlNameTable nameTable)
            : base(nameTable)
        {
            this.AddNamespace("s", "http://schemas.xmlsoap.org/soap/envelope/");
            this.AddNamespace("s11", "http://schemas.xmlsoap.org/soap/envelope/");
            this.AddNamespace("s12", "http://www.w3.org/2003/05/soap-envelope");
            this.AddNamespace("wsaAugust2004", "http://schemas.xmlsoap.org/ws/2004/08/addressing");
            this.AddNamespace("wsa10", "http://www.w3.org/2005/08/addressing");
            this.AddNamespace("i", "http://www.w3.org/2001/XMLSchema-instance");
        }
    }


        private void displayClaimSet(ClaimSet cs)
        {
            Console.WriteLine();
            Console.WriteLine(CLAIM_FORMAT_STRING, "RIGHT", "CLAIM_TYPE", "RESOURCE");
            claimsText.AppendLine(string.Format(CLAIM_FORMAT_STRING, "RIGHT", "CLAIM_TYPE", "RESOURCE")); 

            // display claims for subject of this claimset
            foreach (Claim c in cs)
            {
                displayClaim(c);
            }

            Console.WriteLine();
            Console.Write("ISSUED BY: ");
            claimsText.AppendLine("ISSUED BY: "); 

            // display claims for issuer of this claimset
            if (null == cs.Issuer)
            {
                Console.WriteLine("null");
                claimsText.AppendLine("null");
            }
            else if (object.ReferenceEquals(cs, cs.Issuer))
            {
                // self-asserted claims (issuer is the same as subject)
                Console.WriteLine("self");
                claimsText.AppendLine("self");
            }
            else
            {
                displayClaimSet(cs.Issuer);
            }
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
            string claimType = c.ClaimType.Replace("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/",".../");
            string value = stringizeResource(c.Resource);

            Console.WriteLine(CLAIM_FORMAT_STRING, right, claimType, value);
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
            if (null != key) return string.Format("{0} bit RSA public key (RSACryptoServiceProvider)",key.KeySize);

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