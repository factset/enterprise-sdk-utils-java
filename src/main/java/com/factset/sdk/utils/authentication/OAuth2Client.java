package com.factset.sdk.utils.authentication;

import com.factset.sdk.utils.exceptions.AccessTokenException;
import com.factset.sdk.utils.exceptions.SigningJwsException;

import java.io.IOException;

/**
 * Interface for the OAuth2 code flows Confidential Client and Authorization Code.
 */
public interface OAuth2Client {

    /**
     * Returns the access token.
     * @return The access token for protected resource requests.
     */
    String getAccessToken() throws AccessTokenException, SigningJwsException, IOException;
}
