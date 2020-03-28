using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;

namespace WcfSecurity.SecureService
{
    // NOTE: You can use the "Rename" command on the "Refactor" menu to change the class name "Service1" in code, svc and config file together.
    public class BasicHttpService : ITestService
    {
       

        #region ITestService Members

        public string CheckData(string caller)
        {
            return "Reply from basicHttpService to:" + caller;
        }

        public string GetDate()
        {
            return DateTime.Now.ToString();
        }

        #endregion
    }
}
