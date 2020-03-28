using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Net;
using WcfSecurity.SecurityPolicy;

namespace SecureClient
{
    class Program
    {
        static void Main(string[] args)
        {
            //AuthorizationPolicy authorisationPolicy = new AuthorizationPolicy();
            //authorisationPolicy.GetAllowedOpList("chc\vk23942"); 
            // uncomment the following line after implementation of message security 
            string param = "Test User";
            if (args.Length > 0 && args[0] != null)
                param = args[0]; 

            #region basicHttpBinding
            Console.WriteLine("First trying with basic http binding ..."); 
            using (WcfSecurity.SecureClient.BasicHttpService.TestServiceClient client = new WcfSecurity.SecureClient.BasicHttpService.TestServiceClient())
            {
                //client.ClientCredentials.Windows.ClientCredential.UserName = "vk23942";
                //client.ClientCredentials.Windows.ClientCredential.Domain = "chc";
                //client.ClientCredentials.Windows.ClientCredential.Password = "March(8)";

                Console.WriteLine("Checking CheckData method using basicHttpBinding .....");
                try
                {
                    Console.WriteLine(client.CheckData(param));
                }
                catch (Exception exception)
                {
                    Console.WriteLine("Error occurred:" + exception.Message);
                }

                Console.WriteLine("Checking GetDate method using basicHttpBinding .....");
                try
                {
                    Console.WriteLine("System date as per server is" + client.GetDate());
                }
                catch (Exception exception)
                {
                    Console.WriteLine("Error occurred:" + exception.Message);
                }

            }
            #endregion 

            Console.WriteLine("          "); 
            Console.WriteLine("Now trying with ws http binding ..."); 
            #region wsHttpBinding
            using (WcfSecurity.SecureClient.WSHttpService.TestServiceClient client = new WcfSecurity.SecureClient.WSHttpService.TestServiceClient())
            {
                //client.ClientCredentials.Windows.ClientCredential.UserName = "vk23942";
                //client.ClientCredentials.Windows.ClientCredential.Domain = "chc";
                //client.ClientCredentials.Windows.ClientCredential.Password = "August(21)";

                Console.WriteLine("Checking CheckData method using wsHttpBinding .....");
                try
                {
                    Console.WriteLine(client.CheckData(param));
                }
                catch (Exception exception)
                {
                    Console.WriteLine("Error occurred:" + exception.Message);
                }

                Console.WriteLine("Checking GetDate method using wsHttpBinding .....");
                try
                {
                    Console.WriteLine("System date as per server is" + client.GetDate());
                }
                catch (Exception exception)
                {
                    Console.WriteLine("Error occurred:" + exception.Message);
                }

            }

            #endregion 

            //ServicePointManager.ServerCertificateValidationCallback =   new RemoteCertificateValidationCallback(IgnoreCertificateErrorHandler);

            //using (WcfSecurity.SecureClient.SecureSocketService.TestServiceClient client = new WcfSecurity.SecureClient.SecureSocketService.TestServiceClient())
            //{
            //    client.ClientCredentials.Windows.ClientCredential.UserName = "vk23942";
            //    client.ClientCredentials.Windows.ClientCredential.Domain = "chc";
            //    client.ClientCredentials.Windows.ClientCredential.Password = "August(21)";

            //    Console.WriteLine(client.GetData(10));
            //}
            Console.ReadLine();

        }

        public static bool IgnoreCertificateErrorHandler(object sender,
          X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

    }
}
