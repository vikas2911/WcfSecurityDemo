using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.IdentityModel.Policy;
using System.IdentityModel.Tokens;
using System.IdentityModel.Selectors;
using System.ServiceModel;
using System.Security.Permissions;
using System.IO;
using System.Data;
using System.Text;

[assembly: SecurityPermission(
   SecurityAction.RequestMinimum, Execution = true)]
namespace WcfSecurity.SecurityPolicy
{
    public class AuthorizationPolicy : IAuthorizationPolicy
    {
        string id;
        TextWriter twClaims;
        ClaimsUtil claimsUitl;
        DataSet authInfos; 

        public AuthorizationPolicy()
        {
            id = Guid.NewGuid().ToString();
            
            authInfos = new DataSet("AuthInfo");
            DataTable authInfo = new DataTable("AuthInfo");
            DataColumn domainColumn = new DataColumn("Domain", typeof(System.String));
            DataColumn userColumn = new DataColumn("User", typeof(System.String));
            DataColumn interfaceColumn = new DataColumn("Interface", typeof(System.String));
            DataColumn methodColumn = new DataColumn("Method", typeof(System.String));
            authInfo.Columns.Add(domainColumn);
            authInfo.Columns.Add(userColumn);
            authInfo.Columns.Add(interfaceColumn);
            authInfo.Columns.Add(methodColumn);
            authInfos.Tables.Add(authInfo); 

            authInfos.Tables["AuthInfo"].ReadXml(@"c:\Authorisation.config"); 
        }

        public bool Evaluate(EvaluationContext evaluationContext, ref object state)
        {
            twClaims = File.AppendText(@"c:\Servicelogs\PolicyClaims.logs");
            bool bRet = false;
            CustomAuthState customstate = null;

            // If state is null, then we've not been called before so we need
            // to set up our custom state
            if (state == null)
            {
                customstate = new CustomAuthState();
                state = customstate;
            }
            else
                customstate = (CustomAuthState)state;

            Console.WriteLine("Inside MyAuthorizationPolicy::Evaluate");

            // If we've not added claims yet...
            if (!customstate.ClaimsAdded)
            {
                // Create an empty list of Claims
                IList<Claim> claims = new List<Claim>();

                // Iterate through each of the claimsets in the evaluation context
                foreach (ClaimSet cs in evaluationContext.ClaimSets)
                    // Look for Name claims in the current claimset...
                    foreach (Claim c in cs.FindClaims(ClaimTypes.Name, Rights.PossessProperty))
                        // Get the list of operations the given username is allowed to call...
                        foreach (string s in GetAllowedOpList(c.Resource.ToString()))
                        {
                            twClaims.WriteLine("PolicyClaim:" + s);
                            // Add claims to the list
                            claims.Add(new Claim("http://example.org/claims/allowedoperation", s, Rights.PossessProperty));
                        }

                // Add claims to the evaluation context    
                evaluationContext.AddClaimSet(this, new DefaultClaimSet(this.Issuer, claims));

                // record that we've added claims
                customstate.ClaimsAdded = true;

                // return true, indicating we do not need to be called again.
                bRet = true;
            }
            else
            {
                // Should never get here, but just in case...
                bRet = true;
            }

            twClaims.Close();
            return bRet;
        }

        public ClaimSet Issuer
        {
            get { return ClaimSet.System; }
        }

        public string Id
        {
            get { return id; }
        }

        // This method returns a collection of action strings thet indicate the 
        // operations the specified username is allowed to call.
        public IEnumerable<string> GetAllowedOpList(string username)
        {
            IList<string> ret = new List<string>();

            foreach (DataRow row in authInfos.Tables["AuthInfo"].Rows)
            {
                string resource = @"http://tempuri.org/<Interface>/<Method>"; 
                if (username.Contains(row["User"].ToString()) && username.Contains(row["Domain"].ToString()));
                {
                    resource = resource.Replace("<Interface>", row["Interface"].ToString().Trim());
                    resource = resource.Replace("<Method>", row["Method"].ToString().Trim()); 
                    ret.Add(resource); 
                }
            }
            return ret;
        }

        // internal class for state
        class CustomAuthState
        {
            bool bClaimsAdded;

            public CustomAuthState()
            {
            }

            public bool ClaimsAdded
            {
                get { return bClaimsAdded; }
                set { bClaimsAdded = value; }
            }
        }
    }

}
