package com.factset.sdk.utils.authentication;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import java.net.URI;

/**
 * A builder class for a TokenRequest object using Client Credentials Grant.
 */
public class TokenRequestBuilder {

    private URI uri;
    private SignedJWT signedJwt;

    /**
     * Initialises the TokenRequestBuilder instance.
     */
    public TokenRequestBuilder() {
        // This initialises the TokenRequest states as null and allows the user to "build" the states with the builder
        // methods.
    }

    /**
     * Updates the uri field and returns the updated builder.
     *
     * @param uriParam The URI instance.
     * @return The TokenRequestBuilder.
     */
    public TokenRequestBuilder uri(final URI uriParam) {
        this.uri = uriParam;
        return this;
    }

    /**
     * Updates the signedJwt field and returns the updated builder.
     *
     * @param signedJwtParam The SignedJWT instance.
     * @return The TokenRequestBuilder.
     */
    public TokenRequestBuilder signedJwt(final SignedJWT signedJwtParam) {
        this.signedJwt = signedJwtParam;
        return this;
    }

    /**
     * Creates and returns an instance of the TokenRequest with a ClientCredentialsGrant and the specified URI and
     * SignedJWT.
     *
     * @return The TokenRequest instance.
     */
    public TokenRequest build() {
        return new TokenRequest(
            this.uri,
            new PrivateKeyJWT(this.signedJwt),
            new ClientCredentialsGrant(),
            new Scope()
        );
    }
}
