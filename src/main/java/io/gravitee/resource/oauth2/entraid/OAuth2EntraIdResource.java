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
package io.gravitee.resource.oauth2.entraid;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.utils.UUID;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.reactive.api.context.DeploymentContext;
import io.gravitee.node.api.Node;
import io.gravitee.node.api.utils.NodeUtils;
import io.gravitee.node.container.spring.SpringEnvironmentConfiguration;
import io.gravitee.node.vertx.client.http.VertxHttpClientFactory;
import io.gravitee.plugin.mappers.HttpClientOptionsMapper;
import io.gravitee.plugin.mappers.HttpProxyOptionsMapper;
import io.gravitee.plugin.mappers.SslOptionsMapper;
import io.gravitee.resource.oauth2.api.OAuth2Resource;
import io.gravitee.resource.oauth2.api.OAuth2ResourceException;
import io.gravitee.resource.oauth2.api.OAuth2ResourceMetadata;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import io.gravitee.resource.oauth2.api.openid.UserInfoResponse;
import io.gravitee.resource.oauth2.entraid.configuration.OAuth2EntraIdResourceConfiguration;
import io.gravitee.resource.oauth2.entraid.configuration.OAuth2EntraIdResourceConfigurationEvaluator;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.rxjava3.core.Vertx;
import java.net.URI;
import java.net.URL;
import java.text.ParseException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.inject.Inject;
import lombok.AccessLevel;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

/**
 * Gravitee OAuth2 resource for Microsoft Entra ID (formerly Azure Active Directory).
 *
 * <p><strong>Token validation strategy:</strong> Entra ID does not expose an RFC 7662 introspection
 * endpoint for third-party resource servers. Instead, access tokens issued by Entra ID are JWTs
 * whose integrity can be verified locally using the tenant's public signing keys published at the
 * JWKS endpoint. This resource implements that local validation:
 * <ol>
 *   <li>Parse the incoming access token as a signed JWT.</li>
 *   <li>Fetch (and cache) the tenant's JWKS from
 *       {@code https://login.microsoftonline.com/{tenantId}/discovery/v2.0/keys}.</li>
 *   <li>Verify the JWT signature using the matching public key.</li>
 *   <li>Validate standard claims: {@code exp}, {@code nbf}, {@code iss}, {@code aud}.</li>
 *   <li>Validate the Entra ID-specific {@code tid} (tenant ID) claim.</li>
 * </ol>
 *
 * <p><strong>User info:</strong> The {@code userInfo()} method calls the standard OpenID Connect
 * userinfo endpoint ({@code https://login.microsoftonline.com/{tenantId}/openid/userinfo}) with the
 * Bearer token to retrieve additional user profile claims (name, email, etc.).
 *
 * <p><strong>JWKS caching:</strong> Signing keys are cached in memory and refreshed either after
 * the configured TTL or when a token references an unknown key ID (key rotation).
 *
 * @author GraviteeSource Team
 */
public class OAuth2EntraIdResource extends OAuth2Resource<OAuth2EntraIdResourceConfiguration> implements ApplicationContextAware {

    public static final String ERROR_CHECKING_OAUTH_2_TOKEN = "An error occurs while checking OAuth2 token against Entra ID";
    public static final String ERROR_GETTING_USERINFO = "An error occurs while getting userinfo from Entra ID";

    static final String DEFAULT_MICROSOFT_BASE_URL = "https://login.microsoftonline.com";

    private static final String ENTRA_ID_V2_PATH = "/v2.0";
    private static final String JWKS_PATH = "/discovery/v2.0/keys";
    private static final String USERINFO_PATH = "/openid/userinfo";

    private static final String AUTHORIZATION_HEADER_BEARER_SCHEME = "Bearer ";

    /** JWKS cache TTL: keys are refreshed after 1 hour even without key-rotation events. */
    private static final long JWKS_CACHE_TTL_MS = 60 * 60 * 1_000L;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Logger logger = LoggerFactory.getLogger(OAuth2EntraIdResource.class);

    private ApplicationContext applicationContext;

    private HttpClient httpClient;

    /** RxJava3 Vert.x instance, kept for executing blocking JWKS fetches on the worker pool. */
    private Vertx rxVertx;

    private String userAgent;

    /** Computed from tenantId: {@code https://login.microsoftonline.com/{tenantId}/v2.0} */
    private String authorizationServerUrl;

    /** Computed from tenantId: {@code https://login.microsoftonline.com/{tenantId}/openid/userinfo} */
    private String userInfoEndpointURI;

    /** Computed from tenantId: {@code https://login.microsoftonline.com/{tenantId}/discovery/v2.0/keys} */
    private String jwksUri;

    // JWKS cache, protected by "this" monitor
    private JWKSet jwksCache;
    private long jwksCacheTimestamp;

    @Setter(AccessLevel.PACKAGE)
    private OAuth2EntraIdResourceConfiguration configuration;

    /**
     * Overrides the Microsoft base URL. Defaults to {@value DEFAULT_MICROSOFT_BASE_URL}.
     * Package-private to allow redirection to a local mock server in tests.
     */
    @Setter(AccessLevel.PACKAGE)
    private String microsoftBaseUrl = DEFAULT_MICROSOFT_BASE_URL;

    @Inject
    @Setter
    private DeploymentContext deploymentContext;

    @Override
    public OAuth2EntraIdResourceConfiguration configuration() {
        if (configuration == null) {
            return super.configuration();
        }
        return configuration;
    }

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        configuration = new OAuth2EntraIdResourceConfigurationEvaluator(configuration()).evalNow(deploymentContext);

        String tenantId = configuration().getTenantId();
        authorizationServerUrl = microsoftBaseUrl + "/" + tenantId + ENTRA_ID_V2_PATH;
        userInfoEndpointURI = microsoftBaseUrl + "/" + tenantId + USERINFO_PATH;
        jwksUri = microsoftBaseUrl + "/" + tenantId + JWKS_PATH;

        logger.info(
            "Starting Entra ID OAuth2 resource for tenant '{}' (authorization server: {}, JWKS: {})",
            tenantId,
            authorizationServerUrl,
            jwksUri
        );

        rxVertx = applicationContext.getBean(Vertx.class);

        URI targetUri = URI.create(userInfoEndpointURI);
        int port = targetUri.getPort() != -1 ? targetUri.getPort() : ("https".equals(targetUri.getScheme()) ? 443 : 80);
        URL targetUrl = new URL(targetUri.getScheme(), targetUri.getHost(), port, targetUri.toURL().getFile());

        httpClient = VertxHttpClientFactory.builder()
            .vertx(rxVertx)
            .nodeConfiguration(new SpringEnvironmentConfiguration(applicationContext.getEnvironment()))
            .defaultTarget(targetUrl.toString())
            .httpOptions(HttpClientOptionsMapper.INSTANCE.map(configuration().getHttpClientOptions()))
            .sslOptions(SslOptionsMapper.INSTANCE.map(configuration().getSslOptions()))
            .proxyOptions(HttpProxyOptionsMapper.INSTANCE.map(configuration().getHttpProxyOptions()))
            .build()
            .createHttpClient()
            .getDelegate();

        userAgent = NodeUtils.userAgent(applicationContext.getBean(Node.class));

        // Pre-load the JWKS at startup so the first request does not incur the fetch latency.
        // JWKSet.load() is a blocking call; it is acceptable here because doStart() runs
        // during plugin initialization, outside of the request processing event loop.
        try {
            loadJwks();
        } catch (Exception e) {
            logger.warn(
                "Failed to pre-load JWKS from {}. Token validation will be attempted at first request: {}",
                jwksUri,
                e.getMessage()
            );
        }
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();
        try {
            httpClient.close();
        } catch (IllegalStateException ise) {
            logger.warn(ise.getMessage());
        }
    }

    /**
     * Validates the access token locally by verifying its JWT signature and claims against
     * Entra ID's published public keys.
     *
     * <p>The JWKS is fetched and cached; it is only re-fetched when the cache TTL expires or when
     * the token references an unknown key ID (indicating key rotation). The JWKS fetch is executed
     * on Vert.x's worker thread pool to avoid blocking the event loop.
     */
    @Override
    public void introspect(String accessToken, Handler<OAuth2Response> responseHandler) {
        // Parse the JWT format upfront — fast, no I/O; fail early for non-JWT tokens.
        final SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(accessToken);
        } catch (ParseException e) {
            logger.debug("Access token is not a valid JWT: {}", e.getMessage());
            responseHandler.handle(new OAuth2Response(false, "{\"active\":false}"));
            return;
        }

        // JWKS fetch (if needed) is blocking I/O — run on the worker thread pool.
        rxVertx
            .executeBlocking(() -> validateJwt(signedJWT))
            .subscribe(responseHandler::handle, error -> {
                logger.error(ERROR_CHECKING_OAUTH_2_TOKEN, error);
                responseHandler.handle(new OAuth2Response(error));
            });
    }

    @Override
    public void userInfo(String accessToken, Handler<UserInfoResponse> responseHandler) {
        logger.debug("Getting userinfo from Entra ID endpoint: {}", userInfoEndpointURI);

        final RequestOptions reqOptions = new RequestOptions()
            .setMethod(HttpMethod.GET)
            .setAbsoluteURI(userInfoEndpointURI)
            .putHeader(HttpHeaderNames.USER_AGENT, userAgent)
            .putHeader("X-Gravitee-Request-Id", UUID.toString(UUID.random()))
            .putHeader(HttpHeaderNames.AUTHORIZATION, AUTHORIZATION_HEADER_BEARER_SCHEME + accessToken);

        httpClient
            .request(reqOptions)
            .onFailure(event -> {
                logger.error(ERROR_GETTING_USERINFO, event);
                responseHandler.handle(new UserInfoResponse(event));
            })
            .onSuccess(request ->
                request
                    .response(asyncResponse -> {
                        if (asyncResponse.failed()) {
                            logger.error(ERROR_GETTING_USERINFO, asyncResponse.cause());
                            responseHandler.handle(new UserInfoResponse(asyncResponse.cause()));
                        } else {
                            final HttpClientResponse response = asyncResponse.result();
                            response.bodyHandler(buffer -> {
                                logger.debug("Entra ID userinfo endpoint returned status {}", response.statusCode());
                                if (response.statusCode() == HttpStatusCode.OK_200) {
                                    responseHandler.handle(new UserInfoResponse(true, buffer.toString()));
                                } else {
                                    logger.error(
                                        "An error occurs while getting userinfo from Entra ID. Request ended with status {}: {}",
                                        response.statusCode(),
                                        buffer
                                    );
                                    responseHandler.handle(new UserInfoResponse(new OAuth2ResourceException(ERROR_GETTING_USERINFO)));
                                }
                            });
                        }
                    })
                    .exceptionHandler(event -> {
                        logger.error(ERROR_GETTING_USERINFO, event);
                        responseHandler.handle(new UserInfoResponse(event));
                    })
                    .end()
            );
    }

    /**
     * Returns the user claim field used for analytics logging.
     *
     * <p>Defaults to {@code oid} (Object ID), which is the stable, unique identifier for a user
     * across all applications in an Entra ID tenant. Unlike {@code sub} which is application-specific,
     * {@code oid} remains constant regardless of which application issued the token.
     */
    @Override
    public String getUserClaim() {
        String claim = configuration().getUserClaim();
        if (claim != null && !claim.isEmpty()) {
            return claim;
        }
        return "oid";
    }

    @Override
    public OAuth2ResourceMetadata getProtectedResourceMetadata(String protectedResourceUri) {
        return new OAuth2ResourceMetadata(protectedResourceUri, List.of(authorizationServerUrl), List.of());
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    // -------------------------------------------------------------------------
    // JWT validation internals
    // -------------------------------------------------------------------------

    /**
     * Validates a parsed signed JWT. This method runs on a Vert.x worker thread (called from
     * {@code executeBlocking}) so blocking operations (JWKS HTTP fetch) are acceptable.
     */
    private OAuth2Response validateJwt(SignedJWT signedJWT) {
        try {
            String kid = signedJWT.getHeader().getKeyID();

            // Retrieve (and if necessary refresh) the JWKS.
            JWKSet jwks = getOrRefreshJwks(kid);

            // Build a JWT processor with the current signing keys.
            JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(jwks);
            JWSVerificationKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);

            DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier = buildClaimsVerifier(signedJWT);

            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(keySelector);
            jwtProcessor.setJWTClaimsSetVerifier(claimsVerifier);

            JWTClaimsSet claims = jwtProcessor.process(signedJWT, null);

            // Entra ID-specific: validate the tid (tenant ID) claim.
            String tid = claims.getStringClaim("tid");
            if (tid != null && !configuration().getTenantId().equals(tid)) {
                logger.debug("Token tenant ID '{}' does not match configured tenant '{}'", tid, configuration().getTenantId());
                return new OAuth2Response(false, "{\"active\":false}");
            }

            // Build an RFC 7662-compatible payload enriched with active=true.
            String payload = buildPayload(claims);
            return new OAuth2Response(true, payload);
        } catch (BadJOSEException | JOSEException e) {
            logger.debug("JWT validation failed for tenant '{}': {}", configuration().getTenantId(), e.getMessage());
            return new OAuth2Response(false, "{\"active\":false}");
        } catch (Exception e) {
            logger.error(ERROR_CHECKING_OAUTH_2_TOKEN, e);
            return new OAuth2Response(e);
        }
    }

    /**
     * Builds a {@link DefaultJWTClaimsVerifier} that enforces the Entra ID-specific issuer, the
     * configured audience (if set), expiration, and not-before constraints.
     */
    private DefaultJWTClaimsVerifier<SecurityContext> buildClaimsVerifier(SignedJWT signedJWT) throws Exception {
        // Issuer is different depending on the version of Entra ID
        String version = signedJWT.getJWTClaimsSet().getStringClaim("ver");
        String expectedIssuer;

        if ("1.0".equals(version)) {
            expectedIssuer = "https://sts.windows.net/" + configuration().getTenantId() + "/";
        } else {
            expectedIssuer = microsoftBaseUrl + "/" + configuration().getTenantId() + ENTRA_ID_V2_PATH;
        }

        JWTClaimsSet.Builder exactMatchBuilder = new JWTClaimsSet.Builder().issuer(expectedIssuer);

        String audience = configuration().getAudience();
        if (audience != null && !audience.isEmpty()) {
            exactMatchBuilder.audience(audience);
        }

        // Require at minimum sub, tid, iat, and exp to be present.
        return new DefaultJWTClaimsVerifier<>(exactMatchBuilder.build(), Set.of("sub", "tid", "iat", "exp"));
    }

    /**
     * Returns the cached JWKS, re-fetching from Microsoft if the cache has expired or if the key
     * identified by {@code kid} is not present (indicating key rotation).
     */
    private synchronized JWKSet getOrRefreshJwks(String kid) throws Exception {
        boolean cacheHasKey = jwksCache != null && (kid == null || jwksCache.getKeyByKeyId(kid) != null);
        boolean cacheIsFresh = jwksCache != null && (System.currentTimeMillis() - jwksCacheTimestamp) < JWKS_CACHE_TTL_MS;

        if (cacheHasKey && cacheIsFresh) {
            return jwksCache;
        }

        if (!cacheIsFresh) {
            logger.debug("JWKS cache expired, refreshing from {}", jwksUri);
        } else {
            logger.debug("Key ID '{}' not found in JWKS cache, refreshing from {} (possible key rotation)", kid, jwksUri);
        }

        loadJwks();
        return jwksCache;
    }

    /**
     * Fetches the JWKS from the Microsoft endpoint and updates the in-memory cache.
     * This is a blocking HTTP call — only invoke from a worker thread or during startup.
     */
    private synchronized void loadJwks() throws Exception {
        jwksCache = JWKSet.load(new URL(jwksUri));
        jwksCacheTimestamp = System.currentTimeMillis();
        logger.info("Loaded {} signing key(s) from JWKS endpoint {}", jwksCache.size(), jwksUri);
    }

    /**
     * Builds an RFC 7662-compatible JSON payload from the validated JWT claims.
     * Date claims ({@code exp}, {@code nbf}, {@code iat}) are converted to Unix timestamps
     * (seconds) as required by the RFC.
     */
    private String buildPayload(JWTClaimsSet claims) throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("active", true);

        for (Map.Entry<String, Object> entry : claims.getClaims().entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Date) {
                // RFC 7662 uses seconds; java.util.Date stores milliseconds.
                payload.put(entry.getKey(), ((Date) value).getTime() / 1_000L);
            } else {
                payload.put(entry.getKey(), value);
            }
        }

        return MAPPER.writeValueAsString(payload);
    }
}
