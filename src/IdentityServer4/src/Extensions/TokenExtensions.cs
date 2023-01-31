// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;

using IdentityModel;

using IdentityServer4.Configuration;
using IdentityServer4.Models;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer4.Extensions
{
    /// <summary>
    /// Extensions for Token
    /// </summary>
    public static class TokenExtensions
    {
        /// <summary>
        /// Creates the default JWT payload.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="clock">The clock.</param>
        /// <param name="options">The options</param>
        /// <param name="logger">The logger.</param>
        /// <returns></returns>
        /// <exception cref="Exception">
        /// </exception>
        public static JwtPayload CreateJwtPayload(this Token token, ISystemClock clock, IdentityServerOptions options, ILogger logger)
        {
            var payload = new JwtPayload(
                token.Issuer,
                null,
                null,
                clock.UtcNow.UtcDateTime,
                clock.UtcNow.UtcDateTime.AddSeconds(token.Lifetime));

            foreach (var aud in token.Audiences)
            {
                payload.AddClaim(new Claim(JwtClaimTypes.Audience, aud));
            }

            var amrClaims = token.Claims.Where(x => x.Type == JwtClaimTypes.AuthenticationMethod).ToArray();
            var scopeClaims = token.Claims.Where(x => x.Type == JwtClaimTypes.Scope).ToArray();
            var jsonClaims = token.Claims.Where(x => x.ValueType == IdentityServerConstants.ClaimValueTypes.Json).ToList();
            
            // add confirmation claim if present (it's JSON valued)
            if (token.Confirmation.IsPresent())
            {
                jsonClaims.Add(new Claim(JwtClaimTypes.Confirmation, token.Confirmation, IdentityServerConstants.ClaimValueTypes.Json));
            }

            var normalClaims = token.Claims
                .Except(amrClaims)
                .Except(jsonClaims)
                .Except(scopeClaims);

            payload.AddClaims(normalClaims);

            // scope claims
            if (!scopeClaims.IsNullOrEmpty())
            {
                var scopeValues = scopeClaims.Select(x => x.Value).ToArray();

                if (options.EmitScopesAsSpaceDelimitedStringInJwt)
                {
                    payload.Add(JwtClaimTypes.Scope, string.Join(" ", scopeValues));
                }
                else
                {
                    payload.Add(JwtClaimTypes.Scope, scopeValues);
                }
            }

            // amr claims
            if (!amrClaims.IsNullOrEmpty())
            {
                var amrValues = amrClaims.Select(x => x.Value).Distinct().ToArray();
                payload.Add(JwtClaimTypes.AuthenticationMethod, amrValues);
            }
            
            // deal with json types
            // calling ToArray() to trigger JSON parsing once and so later 
            // collection identity comparisons work for the anonymous type
            try
            {
                var jsonTokens = jsonClaims.Select(x => new { x.Type, JsonValue = JsonSerializer.Deserialize<JsonElement>(x.Value) }).ToArray();

                var jsonObjects = jsonTokens.Where(x => x.JsonValue.ValueKind == JsonValueKind.Object).ToArray();
                var jsonObjectGroups = jsonObjects.GroupBy(x => x.Type).ToArray();
                foreach (var group in jsonObjectGroups)
                {
                    if (payload.ContainsKey(group.Key))
                    {
                        throw new Exception($"Can't add two claims where one is a JSON object and the other is not a JSON object ({group.Key})");
                    }

                    if (group.Skip(1).Any())
                    {
                        // add as array
                        payload.Add(group.Key, group.Select(x => x.JsonValue).ToArray());
                    }
                    else
                    {
                        // add just one
                        payload.Add(group.Key, group.First().JsonValue);
                    }
                }

                var jsonArrays = jsonTokens.Where(x => x.JsonValue.ValueKind == JsonValueKind.Array).ToArray();
                var jsonArrayGroups = jsonArrays.GroupBy(x => x.Type).ToArray();
                foreach (var group in jsonArrayGroups)
                {
                    if (payload.ContainsKey(group.Key))
                    {
                        throw new Exception(
                            $"Can't add two claims where one is a JSON array and the other is not a JSON array ({group.Key})");
                    }

                    var newArr = new List<JsonElement>();
                    foreach (var arrays in group)
                    {
                        newArr.AddRange(arrays.JsonValue.EnumerateArray());
                    }

                    // add just one array for the group/key/claim type
                    payload.Add(group.Key, newArr.ToArray());
                }

                var unsupportedJsonTokens = jsonTokens.Except(jsonObjects).Except(jsonArrays).ToArray();
                var unsupportedJsonClaimTypes = unsupportedJsonTokens.Select(x => x.Type).Distinct().ToArray();
                if (unsupportedJsonClaimTypes.Any())
                {
                    throw new Exception(
                        $"Unsupported JSON type for claim types: {unsupportedJsonClaimTypes.Aggregate((x, y) => x + ", " + y)}");
                }

                return payload;
            }
            catch (Exception ex)
            {
                logger.LogCritical(ex, "Error creating a JSON valued claim");
                throw;
            }
        }

        /// <summary>Creates the JWT payload dictionary.</summary>
        /// <param name="token">The token.</param>
        /// <param name="options">The options.</param>
        /// <param name="clock">The clock.</param>
        /// <param name="logger">The logger.</param>
        /// <returns>
        ///   <br />
        /// </returns>
        public static Dictionary<string, object> CreateJwtPayloadDictionary(this Token token, IdentityServerOptions options, ISystemClock clock, ILogger logger)
        {
            try
            {
                var payload = new Dictionary<string, object>
            {
                { JwtClaimTypes.Issuer, token.Issuer }
            };

                // set times (nbf, exp, iat)
                var now = clock.UtcNow.ToUnixTimeSeconds();
                var exp = now + token.Lifetime;

                payload.Add(JwtClaimTypes.NotBefore, now);
                payload.Add(JwtClaimTypes.IssuedAt, now);
                payload.Add(JwtClaimTypes.Expiration, exp);

                // add audience claim(s)
                if (token.Audiences.Any())
                {
                    if (token.Audiences.Count == 1)
                    {
                        payload.Add(JwtClaimTypes.Audience, token.Audiences.First());
                    }
                    else
                    {
                        payload.Add(JwtClaimTypes.Audience, token.Audiences);
                    }
                }

                // add confirmation claim (if present)
                if (token.Confirmation.IsPresent())
                {
                    payload.Add(JwtClaimTypes.Confirmation,
                        JsonSerializer.Deserialize<JsonElement>(token.Confirmation));
                }

                // scope claims
                var scopeClaims = token.Claims.Where(x => x.Type == JwtClaimTypes.Scope).ToArray();
                if (!scopeClaims.IsNullOrEmpty())
                {
                    var scopeValues = scopeClaims.Select(x => x.Value).ToArray();

                    if (options.EmitScopesAsSpaceDelimitedStringInJwt)
                    {
                        payload.Add(JwtClaimTypes.Scope, string.Join(" ", scopeValues));
                    }
                    else
                    {
                        payload.Add(JwtClaimTypes.Scope, scopeValues);
                    }
                }

                // amr claims
                var amrClaims = token.Claims.Where(x => x.Type == JwtClaimTypes.AuthenticationMethod).ToArray();
                if (!amrClaims.IsNullOrEmpty())
                {
                    var amrValues = amrClaims.Select(x => x.Value).Distinct().ToArray();
                    payload.Add(JwtClaimTypes.AuthenticationMethod, amrValues);
                }

                var simpleClaimTypes = token.Claims.Where(c =>
                        c.Type != JwtClaimTypes.AuthenticationMethod && c.Type != JwtClaimTypes.Scope)
                    .Select(c => c.Type)
                    .Distinct();

                // other claims
                foreach (var claimType in simpleClaimTypes)
                {
                    // we ignore claims that are added by the above code for token verification
                    if (!payload.ContainsKey(claimType))
                    {
                        var claims = token.Claims.Where(c => c.Type == claimType).ToArray();

                        if (claims.Count() > 1)
                        {
                            payload.Add(claimType, AddObjects(claims));
                        }
                        else
                        {
                            payload.Add(claimType, AddObject(claims.First()));
                        }
                    }
                }

                return payload;
            }
            catch (Exception ex)
            {
                logger.LogCritical(ex, "Error creating the JWT payload");
                throw;
            }
        }

        private static IEnumerable<object> AddObjects(IEnumerable<Claim> claims)
        {
            foreach (var claim in claims)
            {
                yield return AddObject(claim);
            }
        }

        private static object AddObject(Claim claim)
        {
            if (claim.ValueType == ClaimValueTypes.Boolean)
            {
                return bool.Parse(claim.Value);
            }

            if (claim.ValueType == ClaimValueTypes.Integer || claim.ValueType == ClaimValueTypes.Integer32)
            {
                return int.Parse(claim.Value);
            }

            if (claim.ValueType == ClaimValueTypes.Integer64)
            {
                return long.Parse(claim.Value);
            }

            if (claim.ValueType == ClaimValueTypes.Double)
            {
                return double.Parse(claim.Value);
            }

            if (claim.ValueType == IdentityServerConstants.ClaimValueTypes.Json)
            {
                return JsonSerializer.Deserialize<JsonElement>(claim.Value);
            }

            return claim.Value;
        }
    }
}