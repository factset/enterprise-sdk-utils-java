package com.factset.sdk.utils.exceptions;

public class AccessTokenException extends Exception {
    public AccessTokenException(final String message) {
        super(message);
    }

    public AccessTokenException(final String message, final Exception innerException) {
        super(message, innerException);
    }
}
