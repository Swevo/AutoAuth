using AutoAuth;
using AutoAuth.Endpoints;
using AutoAuth.Tests;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = WebApplication.CreateBuilder(args);

// Kept open for the app's lifetime: SQLite's ":memory:" database is destroyed when the
// connection closes, so a single shared open connection is required for it to persist.
var connection = new SqliteConnection("DataSource=:memory:");
connection.Open();
builder.Services.AddSingleton(connection);

builder.Services.AddDbContext<TestDbContext>((provider, options) =>
{
    options.UseSqlite(provider.GetRequiredService<SqliteConnection>());
    options.UseOpenIddict();
});

builder.Services.AddAuthorization();

builder.Services.AddAutoAuthServer<TestDbContext>(server => server
    .SetIssuer("https://localhost/")
    .AllowClientCredentialsFlow()
    .UseDevelopmentCertificates());

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
    db.Database.EnsureCreated();
}

app.UseAuthentication();
app.UseAuthorization();
app.MapAutoAuthClientCredentialsEndpoint();

app.Run();

// Exposes the implicitly-generated Program class to WebApplicationFactory<Program>.
public partial class Program
{
}
