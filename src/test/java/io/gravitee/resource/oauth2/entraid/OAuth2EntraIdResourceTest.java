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

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.Mockito.lenient;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.gravitee.el.TemplateEngine;
import io.gravitee.el.spel.context.SecuredResolver;
import io.gravitee.node.api.Node;
import io.gravitee.resource.api.AbstractConfigurableResource;
import io.gravitee.resource.oauth2.api.OAuth2ResourceMetadata;
import io.gravitee.resource.oauth2.entraid.configuration.OAuth2EntraIdResourceConfiguration;
import io.vertx.rxjava3.core.Vertx;
import java.lang.reflect.Field;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationContext;

/**
 * @author GraviteeSource Team
 */
@WireMockTest
@ExtendWith({ MockitoExtension.class })
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class OAuth2EntraIdResourceTest {

    private static final String TENANT_ID = "my-tenant-id";
    private static final String AUDIENCE = "api://my-api-client-id";
    private static final String KEY_ID = "test-key-id-1";

    // RSA key pair shared across all tests (generated once for performance)
    private static RSAKey testSigningKey;
    private static String testJwksJson;
    private static TemplateEngine templateEngine;

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private Node node;

    private OAuth2EntraIdResource resource;
    private OAuth2EntraIdResourceConfiguration configuration;
    private int wireMockPort;

    @BeforeAll
    static void initClass() throws Exception {
        SecuredResolver.initialize(null);
        templateEngine = TemplateEngine.templateEngine();

        // Generate a 2048-bit RSA key pair for signing test tokens
        testSigningKey = new RSAKeyGenerator(2048).keyID(KEY_ID).algorithm(JWSAlgorithm.RS256).keyUse(KeyUse.SIGNATURE).generate();

        testJwksJson = new JWKSet(testSigningKey.toPublicJWK()).toString();
    }

    @BeforeEach
    void before(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        wireMockPort = wireMockRuntimeInfo.getHttpPort();

        resource = new OAuth2EntraIdResource();
        resource.setApplicationContext(applicationContext);
        resource.setDeploymentContext(new TestDeploymentContext(templateEngine));

        // Redirect all Microsoft endpoints to the local WireMock server
        resource.setMicrosoftBaseUrl("http://localhost:" + wireMockPort);

        configuration = new OAuth2EntraIdResourceConfiguration();
        configuration.setTenantId(TENANT_ID);
        configuration.setAudience(AUDIENCE);

        Field configurationField = AbstractConfigurableResource.class.getDeclaredField("configuration");
        configurationField.setAccessible(true);
        configurationField.set(resource, configuration);

        lenient().when(applicationContext.getBean(Node.class)).thenReturn(node);
        lenient().when(applicationContext.getBean(Vertx.class)).thenReturn(Vertx.vertx());

        // Serve the JWKS at the expected Entra ID discovery path
        stubFor(get(urlEqualTo("/" + TENANT_ID + "/discovery/v2.0/keys")).willReturn(aResponse().withStatus(200).withBody(testJwksJson)));
    }

    // -------------------------------------------------------------------------
    // introspect() — valid tokens
    // -------------------------------------------------------------------------

    @Test
    void should_validate_a_valid_token() throws Exception {
        resource.doStart();

        String token = buildSignedJwt(standardClaims().build());

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect(token, response -> {
            assertThat(response.isSuccess()).isTrue();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_include_active_true_and_jwt_claims_in_payload() throws Exception {
        resource.doStart();

        String token = buildSignedJwt(standardClaims().claim("oid", "oid-abc-123").build());

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect(token, response -> {
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getPayload()).contains("\"active\":true");
            assertThat(response.getPayload()).contains("\"oid\":\"oid-abc-123\"");
            assertThat(response.getPayload()).contains("\"iss\":\"http://localhost:" + wireMockPort + "/" + TENANT_ID + "/v2.0\"");
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    // -------------------------------------------------------------------------
    // introspect() — invalid tokens
    // -------------------------------------------------------------------------

    @Test
    void should_reject_an_expired_token() throws Exception {
        resource.doStart();

        Date past = new Date(System.currentTimeMillis() - 3600_000);
        String token = buildSignedJwt(standardClaims().expirationTime(past).build());

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect(token, response -> {
            assertThat(response.isSuccess()).isFalse();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_reject_a_token_with_wrong_audience() throws Exception {
        resource.doStart();

        String token = buildSignedJwt(standardClaims().audience("api://some-other-audience").build());

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect(token, response -> {
            assertThat(response.isSuccess()).isFalse();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_reject_a_token_with_wrong_issuer() throws Exception {
        resource.doStart();

        String token = buildSignedJwt(standardClaims().issuer("https://evil.example.com").build());

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect(token, response -> {
            assertThat(response.isSuccess()).isFalse();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_reject_a_token_with_wrong_tenant_id() throws Exception {
        resource.doStart();

        String token = buildSignedJwt(standardClaims().claim("tid", "some-other-tenant").build());

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect(token, response -> {
            assertThat(response.isSuccess()).isFalse();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_reject_a_token_signed_with_a_different_key() throws Exception {
        resource.doStart();

        // Sign with a different key (not in the published JWKS)
        RSAKey otherKey = new RSAKeyGenerator(2048).keyID("other-key-id").keyUse(KeyUse.SIGNATURE).generate();
        String token = buildSignedJwt(standardClaims().build(), otherKey);

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect(token, response -> {
            assertThat(response.isSuccess()).isFalse();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_reject_a_string_that_is_not_a_jwt() throws Exception {
        resource.doStart();

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect("not-a-jwt-token", response -> {
            assertThat(response.isSuccess()).isFalse();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    // -------------------------------------------------------------------------
    // userInfo()
    // -------------------------------------------------------------------------

    @Test
    void should_get_user_info() throws Exception {
        String userInfoPayload = "{\"oid\": \"abc-123\", \"name\": \"Jane Doe\", \"email\": \"jane@example.com\"}";
        stubFor(get(urlEqualTo("/" + TENANT_ID + "/openid/userinfo")).willReturn(aResponse().withStatus(200).withBody(userInfoPayload)));

        resource.doStart();

        AtomicBoolean check = new AtomicBoolean();
        resource.userInfo("any-access-token", userInfoResponse -> {
            assertThat(userInfoResponse.isSuccess()).isTrue();
            assertThat(userInfoResponse.getPayload()).isEqualTo(userInfoPayload);
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_not_get_user_info_when_server_returns_401() throws Exception {
        stubFor(get(urlEqualTo("/" + TENANT_ID + "/openid/userinfo")).willReturn(aResponse().withStatus(401)));

        resource.doStart();

        AtomicBoolean check = new AtomicBoolean();
        resource.userInfo("expired-access-token", userInfoResponse -> {
            assertThat(userInfoResponse.isSuccess()).isFalse();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_send_bearer_token_in_user_info_request() throws Exception {
        String accessToken = "xxxx-yyyy-zzzz";
        stubFor(
            get(urlEqualTo("/" + TENANT_ID + "/openid/userinfo"))
                .withHeader("Authorization", equalTo("Bearer " + accessToken))
                .willReturn(aResponse().withStatus(200).withBody("{\"oid\": \"abc-123\"}"))
        );

        resource.doStart();

        AtomicBoolean check = new AtomicBoolean();
        resource.userInfo(accessToken, userInfoResponse -> check.set(true));

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);

        verify(
            getRequestedFor(urlEqualTo("/" + TENANT_ID + "/openid/userinfo")).withHeader("Authorization", equalTo("Bearer " + accessToken))
        );
    }

    // -------------------------------------------------------------------------
    // getUserClaim()
    // -------------------------------------------------------------------------

    @Test
    void should_return_oid_as_default_user_claim() {
        assertThat(resource.getUserClaim()).isEqualTo("oid");
    }

    @Test
    void should_return_configured_user_claim_when_set() {
        configuration.setUserClaim("email");
        assertThat(resource.getUserClaim()).isEqualTo("email");
    }

    // -------------------------------------------------------------------------
    // getProtectedResourceMetadata()
    // -------------------------------------------------------------------------

    @Test
    void should_return_correct_authorization_server_in_metadata() throws Exception {
        resource.doStart();

        OAuth2ResourceMetadata metadata = resource.getProtectedResourceMetadata("https://my-api.example.com");
        assertAll(
            () -> assertThat(metadata.protectedResourceUri()).isEqualTo("https://my-api.example.com"),
            () -> assertThat(metadata.authorizationServers()).hasSize(1),
            () ->
                assertThat(metadata.authorizationServers().get(0)).isEqualTo(
                    "http://localhost:" + wireMockPort + "/" + TENANT_ID + "/v2.0"
                ),
            () -> assertThat(metadata.scopesSupported()).isEmpty()
        );
    }

    // -------------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------------

    /**
     * Returns a {@link JWTClaimsSet.Builder} pre-populated with valid claims for the test tenant.
     */
    private JWTClaimsSet.Builder standardClaims() {
        String issuer = "http://localhost:" + wireMockPort + "/" + TENANT_ID + "/v2.0";
        return new JWTClaimsSet.Builder()
            .issuer(issuer)
            .audience(AUDIENCE)
            .subject("test-subject-sub")
            .claim("oid", "test-oid-123")
            .claim("tid", TENANT_ID)
            .claim("ver", "2.0")
            .issueTime(new Date())
            .notBeforeTime(new Date())
            .expirationTime(new Date(System.currentTimeMillis() + 3_600_000L));
    }

    private String buildSignedJwt(JWTClaimsSet claims) throws Exception {
        return buildSignedJwt(claims, testSigningKey);
    }

    private String buildSignedJwt(JWTClaimsSet claims, RSAKey signingKey) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new RSASSASigner(signingKey));
        return jwt.serialize();
    }
}
