using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using Microsoft.AspNetCore.Http.Authentication;

namespace AuthWithLinkedIn
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add authentication services
            services.AddAuthentication(
                options => options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme);

            // Add framework services.
            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            // Add the cookie middleware
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                LoginPath = new PathString("/login"),
                LogoutPath = new PathString("/logout")
            });

            // Add the OAuth2 middleware
            app.UseOAuthAuthentication(new OAuthOptions
            {
                // We need to specify an Authentication Scheme
                AuthenticationScheme = "LinkedIn",

                // Configure the LinkedIn Client ID and Client Secret
                ClientId = Configuration["linkedin:clientId"],
                ClientSecret = Configuration["linkedin:clientSecret"],

                // Set the callback path, so LinkedIn will call back to http://APP_URL/signin-linkedin
                // Also ensure that you have added the URL as an Authorized Redirect URL in your LinkedIn application
                CallbackPath = new PathString("/signin-linkedin"),

                // Configure the LinkedIn endpoints
                AuthorizationEndpoint = "https://www.linkedin.com/oauth/v2/authorization",
                TokenEndpoint = "https://www.linkedin.com/oauth/v2/accessToken",
                UserInformationEndpoint = "https://api.linkedin.com/v1/people/~:(id,formatted-name,email-address,picture-url)",

                Scope = { "r_basicprofile", "r_emailaddress" },

                /*Events = new OAuthEvents
                {
                    // The OnCreatingTicket event is called after the user has been authenticated and the OAuth middleware has
                    // created an auth ticket. We need to manually call the UserInformationEndpoint to retrieve the user's information,
                    // parse the resulting JSON to extract the relevant information, and add the correct claims.
                    OnCreatingTicket = async context =>
                    {
                        // Retrieve user info
                        var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                        request.Headers.Add("x-li-format", "json"); // Tell LinkedIn we want the result in JSON, otherwise it will return XML

                        var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
                        response.EnsureSuccessStatusCode();

                        // Extract the user info object
                        var user = JObject.Parse(await response.Content.ReadAsStringAsync());

                        // Add the Name Identifier claim
                        var userId = user.Value<string>("id");
                        if (!string.IsNullOrEmpty(userId))
                        {
                            context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId, ClaimValueTypes.String, context.Options.ClaimsIssuer));
                        }

                        // Add the Name claim
                        var formattedName = user.Value<string>("formattedName");
                        if (!string.IsNullOrEmpty(formattedName))
                        {
                            context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, formattedName, ClaimValueTypes.String, context.Options.ClaimsIssuer));
                        }

                        // Add the email address claim
                        var email = user.Value<string>("emailAddress");
                        if (!string.IsNullOrEmpty(email))
                        {
                            context.Identity.AddClaim(new Claim(ClaimTypes.Email, email, ClaimValueTypes.String,
                                context.Options.ClaimsIssuer));
                        }

                        // Add the Profile Picture claim
                        var pictureUrl = user.Value<string>("pictureUrl");
                        if (!string.IsNullOrEmpty(email))
                        {
                            context.Identity.AddClaim(new Claim("profile-picture", pictureUrl, ClaimValueTypes.String,
                                context.Options.ClaimsIssuer));
                        }
                    }
                }*/
            });

            // Listen for requests on the /login path, and issue a challenge to log in with the LinkedIn middleware
            app.Map("/login", builder =>
            {
                builder.Run(async context =>
                {
                    // Return a challenge to invoke the LinkedIn authentication scheme
                    await context.Authentication.ChallengeAsync("LinkedIn", new AuthenticationProperties() { RedirectUri = "/" });
                });
            });

            // Listen for requests on the /logout path, and sign the user out
            app.Map("/logout", builder =>
            {
                builder.Run(async context =>
                {
                    // Sign the user out of the authentication middleware (i.e. it will clear the Auth cookie)
                    await context.Authentication.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                    // Redirect the user to the home page after signing out
                    context.Response.Redirect("/");
                });
            });

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
