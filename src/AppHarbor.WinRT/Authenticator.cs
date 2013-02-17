using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Authentication.Web;

namespace AppHarbor.WinRT
{
	public static class Authenticator
	{
		public const string ReturnUrl = "http://appharbor.com";
		public const string RequestUrlFormat = "https://appharbor.com/user/authorizations/new?client_id={0}&redirect_uri={1}";
		public const string TokensUrl = "https://appharbor.com/tokens";

		public static async Task<string> Authenticate(string clientId, string clientSecret)
		{		
			var webAuthenticationResult = await WebAuthenticationBroker.AuthenticateAsync(
											WebAuthenticationOptions.None,
											new Uri(string.Format(RequestUrlFormat, clientId, ReturnUrl)),
											new Uri(ReturnUrl));

			if (webAuthenticationResult.ResponseStatus == WebAuthenticationStatus.Success)
			{
				string code = webAuthenticationResult.ResponseData.Substring(webAuthenticationResult.ResponseData.LastIndexOf("code=", System.StringComparison.Ordinal) + 5);

				var httpClient = new HttpClient { BaseAddress = new Uri(TokensUrl) };

				HttpContent content = new FormUrlEncodedContent(new[]
				{
					new KeyValuePair<string, string>("client_id", clientId),
					new KeyValuePair<string, string>("client_secret", clientSecret),
					new KeyValuePair<string, string>("code", code)
				});

				var response = await httpClient.PostAsync(httpClient.BaseAddress, content);

				var con = await response.Content.ReadAsStringAsync();
				return con.Substring(con.IndexOf('=') + 1);

			}

			return null;
		}
	}
}
