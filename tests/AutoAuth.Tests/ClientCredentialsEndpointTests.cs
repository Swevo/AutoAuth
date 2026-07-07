using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AutoAuth.Tests;

public sealed class ClientCredentialsEndpointTests : IClassFixture<AutoAuthWebApplicationFactory>, IAsyncLifetime
{
    private readonly AutoAuthWebApplicationFactory _factory;

    public ClientCredentialsEndpointTests(AutoAuthWebApplicationFactory factory)
    {
        _factory = factory;
    }

    public async Task InitializeAsync() => await _factory.SeedDefaultClientAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private HttpClient CreateHttpsClient() => _factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost"),
    });

    [Fact]
    public async Task Exchange_WithValidClientCredentials_ReturnsAccessToken()
    {
        using var client = CreateHttpsClient();

        var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = AutoAuthWebApplicationFactory.ClientId,
            ["client_secret"] = AutoAuthWebApplicationFactory.ClientSecret,
            ["scope"] = "api1",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var payload = await response.Content.ReadFromJsonAsync<TokenResponse>();
        payload.Should().NotBeNull();
        payload!.AccessToken.Should().NotBeNullOrWhiteSpace();
        payload.TokenType.Should().Be("Bearer");
    }

    [Fact]
    public async Task Exchange_WithWrongSecret_ReturnsInvalidClientError()
    {
        using var client = CreateHttpsClient();

        var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = AutoAuthWebApplicationFactory.ClientId,
            ["client_secret"] = "wrong-secret",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var payload = await response.Content.ReadFromJsonAsync<ErrorResponse>();
        payload!.Error.Should().Be("invalid_client");
    }

    [Fact]
    public async Task Exchange_WithUnknownClient_ReturnsInvalidClientError()
    {
        using var client = CreateHttpsClient();

        var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "does-not-exist",
            ["client_secret"] = "whatever",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var payload = await response.Content.ReadFromJsonAsync<ErrorResponse>();
        payload!.Error.Should().Be("invalid_client");
    }

    [Fact]
    public async Task Exchange_WithUnsupportedGrantType_ReturnsUnsupportedGrantTypeError()
    {
        using var client = CreateHttpsClient();

        var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = "someone",
            ["password"] = "whatever",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var payload = await response.Content.ReadFromJsonAsync<ErrorResponse>();
        payload!.Error.Should().Be("unsupported_grant_type");
    }

    private sealed class TokenResponse
    {
        [System.Text.Json.Serialization.JsonPropertyName("access_token")]
        public string? AccessToken { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("token_type")]
        public string? TokenType { get; set; }
    }

    private sealed class ErrorResponse
    {
        public string? Error { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("error_description")]
        public string? ErrorDescription { get; set; }
    }
}
