package com.factset.sdk.utils.authentication;

/**
 * Contains the constants used by the ConfidentialClient to perform requests for both the metadata of the Well
 * Known URI and the access token.
 */
public final class Constants {

    // confidential client assertion JWT
    public static final int CC_JWT_NOT_BEFORE_SECS = 5;
    public static final int CC_JWT_EXPIRE_AFTER_SECS = 300;

    // default values
    public static final String FACTSET_WELL_KNOWN_URI = "https://auth.factset.com/.well-known/openid-configuration";

    private Constants() {
        throw new IllegalStateException("Utility class");
    }
}
