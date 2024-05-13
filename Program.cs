using System.Text;
using AspJwtDemo;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddTransient<ITokenHelper, JwtTokenHelper>();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services
    // .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddAuthentication(x =>
    {
        x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        x.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        x.DefaultForbidScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(
        options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("supersecret_that_should_be_stored_in_a_secret_manager")),
                ValidIssuer = "http://localhost:5000",
                ValidAudience = "http://localhost:5000"
            };
        }
    );

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Admin", policy => policy.RequireClaim("admin", "true"));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app
    .MapGet(
        "/public-route",
        () => Results.Ok("Hello, World!")
    )
    .WithOpenApi();

app.MapGet(
        "/private-route",
        [Authorize]() => Results.Ok("Hello from private route!")
    )
    .WithOpenApi();

app.MapGet(
    "/admin-route-policy",
    [Authorize("Admin")]() => Results.Ok("Hello from admin route! Protected by policy!")
);

app.MapGet(
        "/admin-route-claim",
        () => Results.Ok("Hello from admin route! Protected by claim!")
    )
    .RequireAuthorization()
    .AddEndpointFilter(
        async (context, next) =>
        {
            if (!context.HttpContext.User.HasClaim("admin", "true"))
            {
                return Results.Forbid();
            }

            return await next(context);
        }
    )
    .WithOpenApi();

app.MapPost("/token", (ITokenHelper jwtHelper, TokenGenerationRequest tokenRequest) => Results.Ok(jwtHelper.GetToken(tokenRequest)));

app.Run();
