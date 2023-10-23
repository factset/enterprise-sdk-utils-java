package com.factset.sdk.utils.authentication;

import com.factset.sdk.utils.exceptions.AccessTokenException;
import com.factset.sdk.utils.exceptions.AuthServerMetadataContentException;
import com.factset.sdk.utils.exceptions.AuthServerMetadataException;
import com.factset.sdk.utils.exceptions.ConfigurationException;
import com.factset.sdk.utils.exceptions.SigningJwsException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class that supports FactSet's implementation of the OAuth 2.0 client credentials flow. This class
 * provides methods that retrieve an access token which can be used to authenticate against FactSet's APIs. It takes
 * care of fetching the token, caching it and refreshing it (when expired) as needed.
 */
public class ConfidentialClient implements OAuth2Client {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfidentialClient.class);
    private final Configuration config;
    private OIDCProviderMetadata providerMetadata;
    private final RequestOptions requestOptions;
    private TokenRequestBuilder tokenRequestBuilder;
    private long jwsIssuedAt;
    private long accessTokenExpireTime;
    private AccessToken accessToken;

    /**
     * Creates a new ConfidentialClient. When setting up the OAuth 2.0 client, this constructor reaches out to
     * FactSet's well-known URI to retrieve metadata about its authorization server. This information along with
     * information about the OAuth 2.0 client is stored and used whenever a new access token is fetched.
     *
     * @param configPath The path towards the file to pe parsed.
     * @throws AuthServerMetadataContentException If Meta Issuer or Meta Token Endpoint is missing.
     * @throws AuthServerMetadataException        If reading from URL is unsuccessful.
     * @throws ConfigurationException             If JWK required keys are missing from the RSA or any keys with a value
     *                                            that is null or an empty string.
     */
    public ConfidentialClient(final String configPath)
        throws AuthServerMetadataContentException, AuthServerMetadataException,
        ConfigurationException {
        this(new Configuration(configPath));
    }

    /**
     * Creates a new ConfidentialClient. When setting up the OAuth 2.0 client, this constructor reaches out to
     * FactSet's well-known URI to retrieve metadata about its authorization server. This information along with
     * information about the OAuth 2.0 client is stored and used whenever a new access token is fetched.
     *
     * @param configPath The path towards the file to pe parsed.
     * @param requestOptions Object that can configure options like proxy and SSL settings
     * @throws AuthServerMetadataContentException If Meta Issuer or Meta Token Endpoint is missing.
     * @throws AuthServerMetadataException        If reading from URL is unsuccessful.
     * @throws ConfigurationException             If JWK required keys are missing from the RSA or any keys with a value
     *                                            that is null or an empty string.
     */
    public ConfidentialClient(final String configPath, RequestOptions requestOptions)
            throws AuthServerMetadataContentException, AuthServerMetadataException,
            ConfigurationException {
        this(new Configuration(configPath), requestOptions);
    }

    /**
     * Creates a new ConfidentialClient. When setting up the OAuth 2.0 client, this constructor reaches out to
     * FactSet's well-known URI to retrieve metadata about its authorization server. This information along with
     * information about the OAuth 2.0 client is stored and used whenever a new access token is fetched.
     *
     * @param config Configuration object.
     * @throws AuthServerMetadataContentException If Meta Issuer or Meta Token Endpoint is missing.
     * @throws AuthServerMetadataException        If reading from URL is unsuccessful.
     * @throws NullPointerException               Unchecked exception, if config is null.
     */
    public ConfidentialClient(final Configuration config)
        throws AuthServerMetadataContentException, AuthServerMetadataException {
        Objects.requireNonNull(config, "Configuration object must not be null");
        this.config = config;
        LOGGER.debug("Finished initialising configuration");
        this.requestOptions = new RequestOptions.RequestOptionsBuilder().build();

        this.requestProviderMetadata();
    }

    /**
     * Creates a new ConfidentialClient. When setting up the OAuth 2.0 client, this constructor reaches out to
     * FactSet's well-known URI to retrieve metadata about its authorization server. This information along with
     * information about the OAuth 2.0 client is stored and used whenever a new access token is fetched.
     *
     * @param config Configuration object.
     * @param requestOptions Object that can configure options like proxy and SSL settings
     * @throws AuthServerMetadataContentException If Meta Issuer or Meta Token Endpoint is missing.
     * @throws AuthServerMetadataException        If reading from URL is unsuccessful.
     * @throws NullPointerException               Unchecked exception, if config is null.
     */
    public ConfidentialClient(final Configuration config, RequestOptions requestOptions)
            throws AuthServerMetadataContentException, AuthServerMetadataException {
        Objects.requireNonNull(config, "Configuration object must not be null");
        this.config = config;
        LOGGER.debug("Finished initialising configuration");
        this.requestOptions = requestOptions;

        this.requestProviderMetadata();
    }

    /**
     * Creates a new ConfidentialClient. When setting up the OAuth 2.0 client, this constructor reaches out to
     * FactSet's well-known URI to retrieve metadata about its authorization server. This information along with
     * information about the OAuth 2.0 client is stored and used whenever a new access token is fetched.
     *
     * @param configPath    The path towards the file to pe parsed.
     * @param tokReqBuilder The TokenRequest builder, used to build custom TokenRequest instances.
     * @throws AuthServerMetadataContentException If Meta Issuer or Meta Token Endpoint is missing.
     * @throws AuthServerMetadataException        If reading from URL is unsuccessful.
     * @throws ConfigurationException             If JWK required keys are missing from the RSA or any keys with a value
     *                                            that is null or an empty string.
     */
    protected ConfidentialClient(final String configPath, final TokenRequestBuilder tokReqBuilder)
        throws AuthServerMetadataContentException,
        AuthServerMetadataException,
        ConfigurationException {
        this(new Configuration(configPath));
        this.tokenRequestBuilder = tokReqBuilder.uri(this.providerMetadata.getTokenEndpointURI());
    }

    /**
     * Creates a new ConfidentialClient. When setting up the OAuth 2.0 client, this constructor reaches out to
     * FactSet's well-known URI to retrieve metadata about its authorization server. This information along with
     * information about the OAuth 2.0 client is stored and used whenever a new access token is fetched.
     *
     * @param config        Configuration object.
     * @param tokReqBuilder The TokenRequest builder, used to build custom TokenRequest instances.
     * @throws AuthServerMetadataContentException If Meta Issuer or Meta Token Endpoint is missing.
     * @throws AuthServerMetadataException        If reading from URL is unsuccessful.
     * @throws NullPointerException               Unchecked exception, if config is null.
     */
    protected ConfidentialClient(final Configuration config, final TokenRequestBuilder tokReqBuilder)
        throws AuthServerMetadataContentException,
        AuthServerMetadataException {
        this(config);
        this.tokenRequestBuilder = tokReqBuilder.uri(this.providerMetadata.getTokenEndpointURI());
    }

    /**
     * Creates a new ConfidentialClient. When setting up the OAuth 2.0 client, this constructor reaches out to
     * FactSet's well-known URI to retrieve metadata about its authorization server. This information along with
     * information about the OAuth 2.0 client is stored and used whenever a new access token is fetched.
     *
     * @param config        Configuration object.
     * @param tokReqBuilder The TokenRequest builder, used to build custom TokenRequest instances.
     * @param requestOptions Object that can configure options like proxy and SSL settings
     * @throws AuthServerMetadataContentException If Meta Issuer or Meta Token Endpoint is missing.
     * @throws AuthServerMetadataException        If reading from URL is unsuccessful.
     * @throws NullPointerException               Unchecked exception, if config is null.
     */
    protected ConfidentialClient(final Configuration config, final TokenRequestBuilder tokReqBuilder, RequestOptions requestOptions)
            throws AuthServerMetadataContentException,
            AuthServerMetadataException {
        this(config, requestOptions);
        this.tokenRequestBuilder = tokReqBuilder.uri(this.providerMetadata.getTokenEndpointURI());
    }

    /**
     * Returns an access token that can be used for authentication. If the cache contains a valid access token,
     * it's returned. Otherwise, a new access token is retrieved from FactSet's authorization server. The access
     * token should be used immediately and not stored to avoid any issues with token expiry. The access token is
     * used in the Authorization header when accessing FactSet's APIs.
     *
     * @return The access token in string format.
     * @throws AccessTokenException If it can't make a successful request or parse the TokenRequest.
     * @throws SigningJwsException  If the signing of the JWS fails.
     */
    @Override
    public String getAccessToken() throws AccessTokenException, SigningJwsException {
        if (this.isCachedTokenValid()) {
            LOGGER.info("Retrieved access token which expires in: {} seconds", TimeUnit.MILLISECONDS.toSeconds(this.accessTokenExpireTime - System.currentTimeMillis()));
            return this.accessToken.toString();
        }

        return this.fetchAccessToken();
    }

    private void requestProviderMetadata() throws AuthServerMetadataContentException, AuthServerMetadataException {
        LOGGER.debug("Attempting to get response from Well Known URI");
        URL wellKnownURL = this.config.getWellKnownUrl();
        InputStream stream;

        try {
            HttpURLConnection conn = (HttpURLConnection) wellKnownURL.openConnection(this.requestOptions.getProxy());
            if (conn instanceof HttpsURLConnection) {
                HttpsURLConnection sslConn = (HttpsURLConnection) conn;
                sslConn.setHostnameVerifier(this.requestOptions.getHostnameVerifier());
                sslConn.setSSLSocketFactory(this.requestOptions.getSslSocketFactory());
            }

            stream = conn.getInputStream();

            final String providerInfo = IOUtils.readInputStreamToString(stream);
            this.providerMetadata = OIDCProviderMetadata.parse(providerInfo);
        } catch (final ParseException e) {
            throw new AuthServerMetadataContentException("Content of WellKnownUri has errors: " +
                    this.config.getWellKnownUrl().toString(), e);
        } catch (final IOException e) {
            throw new AuthServerMetadataException("Error retrieving contents from WellKnownUri: " +
                    this.config.getWellKnownUrl().toString(), e);
        }
        LOGGER.debug("Response received from Well Known URI");

        this.tokenRequestBuilder =
                new TokenRequestBuilder().uri(this.providerMetadata.getTokenEndpointURI());
    }

    private boolean isCachedTokenValid() {
        if (this.accessToken == null) {
            return false;
        }

        return System.currentTimeMillis() < this.accessTokenExpireTime;
    }

    private String fetchAccessToken() throws AccessTokenException, SigningJwsException {
        LOGGER.debug("Fetching a new access token...");

        final TokenResponse tokenRes;
        try {
            final SignedJWT signedJwt = this.getSignedJwt();
            final TokenRequest tokenRequest = this.tokenRequestBuilder.signedJwt(signedJwt).build();

            final HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
            httpRequest.setProxy(this.requestOptions.getProxy());
            httpRequest.setHostnameVerifier(this.requestOptions.getHostnameVerifier());
            httpRequest.setSSLSocketFactory(this.requestOptions.getSslSocketFactory());

            logTokenRequest(httpRequest);

            final HTTPResponse res = httpRequest.send();
            logTokenResponse(res);

            tokenRes = TokenResponse.parse(res);
        } catch (final IOException | ParseException e) {
            throw new AccessTokenException("Error attempting to get the access token", e);
        }

        if (tokenRes.indicatesSuccess()) {
            this.accessToken = tokenRes.toSuccessResponse().getTokens().getAccessToken();
            this.accessTokenExpireTime =
                this.jwsIssuedAt + TimeUnit.SECONDS.toMillis(this.accessToken.getLifetime());
            LOGGER.info("Fetched access token which expires in: {} seconds", this.accessToken.getLifetime());
            return this.accessToken.toString();
        }

        if (tokenRes.toErrorResponse().getErrorObject() == null ||
            tokenRes.toErrorResponse().getErrorObject().getDescription() == null) {
            throw new AccessTokenException("Unsuccessful token response: Failed to authenticate or parse the token");
        }

        throw new AccessTokenException("Unsuccessful token response: " +
            tokenRes.toErrorResponse().getErrorObject().getDescription());
    }

    private void logTokenRequest(HTTPRequest req)
    {
        LOGGER.trace(
            "Token Request: {} {} headers={} body={}",
            req.getMethod(), req.getURL(), req.getHeaderMap(), req.getQuery()
        );
    }

    private static void logTokenResponse(HTTPResponse res)
    {
        LOGGER.trace(
            "Token Response: {} {} headers={} body={}",
            res.getStatusCode(), res.getStatusMessage(), res.getHeaderMap(), res.getContent()
        );
    }

    protected SignedJWT getSignedJwt() throws SigningJwsException
    {
        LOGGER.debug("Signing the JWT...");

        final RSAKey jwk = this.config.getJwk();
        final RSASSASigner signer;
        try {
            signer = new RSASSASigner(jwk);
        } catch (final JOSEException e) {
            throw new SigningJwsException("Unable to create signer", e);
        }

        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID()).build();

        final String[] audiences = {this.providerMetadata.getIssuer().toString()};

        final ClientID clientID = new ClientID(this.config.getClientId());
        final List<Audience> aud = Audience.create(audiences);

        this.jwsIssuedAt = System.currentTimeMillis();
        final Date exp = new Date(this.jwsIssuedAt + TimeUnit.SECONDS.toMillis(Constants.CC_JWT_EXPIRE_AFTER_SECS));
        final Date nbf = new Date(this.jwsIssuedAt - TimeUnit.SECONDS.toMillis(Constants.CC_JWT_NOT_BEFORE_SECS));
        final Date iat = new Date(this.jwsIssuedAt);

        final JWTID jti = new JWTID();

        final JWTClaimsSet payload = new JWTAuthenticationClaimsSet(clientID, aud, exp, nbf, iat, jti).toJWTClaimsSet();

        final SignedJWT signedJWT = new SignedJWT(header, payload);

        try {
            signedJWT.sign(signer);
        } catch (final IllegalStateException | JOSEException e) {
            throw new SigningJwsException("Failed signing of the JWS", e);
        }

        LOGGER.debug("JWT signed successfully");
        return signedJWT;
    }
}
