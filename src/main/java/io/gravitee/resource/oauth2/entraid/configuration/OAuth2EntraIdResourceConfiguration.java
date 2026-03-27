/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.resource.oauth2.entraid.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.gravitee.plugin.annotation.ConfigurationEvaluator;
import io.gravitee.plugin.configurations.http.HttpClientOptions;
import io.gravitee.plugin.configurations.http.HttpProxyOptions;
import io.gravitee.plugin.configurations.ssl.SslOptions;
import io.gravitee.resource.api.ResourceConfiguration;
import lombok.AccessLevel;
import lombok.Data;
import lombok.Setter;

/**
 * Configuration for the Microsoft Entra ID (formerly Azure Active Directory) OAuth2 resource.
 *
 * <p>Entra ID access tokens are JWTs validated locally using the tenant's public signing keys.
 * The JWKS endpoint is automatically derived from the tenant ID:
 * {@code https://login.microsoftonline.com/{tenantId}/discovery/v2.0/keys}
 *
 * <p>The userinfo endpoint for fetching user profile claims is:
 * {@code https://login.microsoftonline.com/{tenantId}/openid/userinfo}
 *
 * @author GraviteeSource Team
 */
@ConfigurationEvaluator
@Data
public class OAuth2EntraIdResourceConfiguration implements ResourceConfiguration {

    /**
     * The Microsoft Entra ID tenant ID (also called Directory ID).
     * Can be found in the Azure portal under Azure Active Directory > Properties.
     * Supports Expression Language.
     */
    private String tenantId;

    /**
     * The expected audience ({@code aud} claim) for incoming access tokens.
     * In Entra ID, this is typically the Application ID URI (e.g., {@code api://{clientId}})
     * or the client ID of the resource application that the token was issued for.
     * <p>
     * This field is required to prevent token confusion attacks — without it, any valid
     * Entra ID token from the same tenant could be accepted by your API.
     * Supports Expression Language.
     */
    private String audience;

    /**
     * The claim used to identify the end user in analytics logs.
     * Defaults to {@code oid} (Object ID), which is stable across all applications in Entra ID.
     * Use {@code sub} if you need the per-application user identifier.
     * Supports EL.
     */
    private String userClaim = "oid";

    @JsonProperty("http")
    private HttpClientOptions httpClientOptions = new HttpClientOptions();

    @JsonProperty("proxy")
    private HttpProxyOptions httpProxyOptions = new HttpProxyOptions();

    @JsonProperty("ssl")
    @Setter(AccessLevel.NONE)
    private SslOptions sslOptions;

    public void setSslOptions(SslOptions sslOptions) {
        if (sslOptions == null) {
            this.sslOptions = SslOptions.builder().hostnameVerifier(false).trustAll(true).build();
            return;
        }
        this.sslOptions = sslOptions;
    }
}
