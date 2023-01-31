// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using System.Threading.Tasks;
using static IdentityServer4.IdentityServerConstants;

namespace IdentityServer4.Services
{
    /// <summary>
    /// Default token creation service
    /// </summary>
    public class DefaultTokenCreationService : ITokenCreationService
    {
        /// <summary>
        /// The key service
        /// </summary>
        protected readonly IKeyMaterialService Keys;

        /// <summary>
        /// The logger
        /// </summary>
        protected readonly ILogger Logger;

        /// <summary>
        ///  The clock
        /// </summary>
        protected readonly ISystemClock Clock;

        /// <summary>
        /// The options
        /// </summary>
        protected readonly IdentityServerOptions Options;

        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultTokenCreationService"/> class.
        /// </summary>
        /// <param name="clock">The options.</param>
        /// <param name="keys">The keys.</param>
        /// <param name="options">The options.</param>
        /// <param name="logger">The logger.</param>
        public DefaultTokenCreationService(
            ISystemClock clock,
            IKeyMaterialService keys,
            IdentityServerOptions options,
            ILogger<DefaultTokenCreationService> logger)
        {
            Clock = clock;
            Keys = keys;
            Options = options;
            Logger = logger;
        }

        /// <summary>
        /// Creates the token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>
        /// A protected and serialized security token
        /// </returns>
        public virtual async Task<string> CreateTokenAsync(Token token)
        {
            var header = await CreateHeaderElementsAsync(token);
            var payload = await CreatePayloadStringAsync(token);

            return await CreateJwtAsync(token, payload, header);
        }

        /// <summary>Creates the payload string asynchronous.</summary>
        /// <param name="token">The token.</param>
        /// <returns>
        ///   <br />
        /// </returns>
        protected virtual ValueTask<string> CreatePayloadStringAsync(Token token)
        {
            var payload = token.CreateJwtPayloadDictionary(Options, Clock, Logger);
            return ValueTask.FromResult(JsonSerializer.Serialize(payload));
        }

        /// <summary>
        /// Creates the header elements asynchronous.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        protected virtual ValueTask<Dictionary<string, object>> CreateHeaderElementsAsync(Token token)
        {
            var additionalHeaderElements = new Dictionary<string, object>();

            if (token.Type == TokenTypes.AccessToken)
            {
                if (Options.AccessTokenJwtType.IsPresent())
                {
                    additionalHeaderElements.Add("typ", Options.AccessTokenJwtType);
                }
            }

            return ValueTask.FromResult(additionalHeaderElements);
        }

        /// <summary>
        /// Applies the signature to the JWT
        /// </summary>
        /// <param name="jwt">The JWT object.</param>
        /// <returns>The signed JWT</returns>
        protected virtual Task<string> CreateJwtAsync(JwtSecurityToken jwt)
        {
            var handler = new JwtSecurityTokenHandler();
            return Task.FromResult(handler.WriteToken(jwt));
        }

        /// <summary>
        /// Creates JWT token
        /// </summary>
        /// <param name="token"></param>
        /// <param name="payload"></param>
        /// <param name="headerElements"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        protected virtual async Task<string> CreateJwtAsync(Token token, string payload, Dictionary<string, object> headerElements)
        {
            var credential = await Keys.GetSigningCredentialsAsync(token.AllowedSigningAlgorithms);

            if (credential == null)
            {
                throw new InvalidOperationException("No signing credential is configured. Can't create JWT token");
            }

            var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
            return handler.CreateToken(payload, credential, headerElements);
        }
    }
}