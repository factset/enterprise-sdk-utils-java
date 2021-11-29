package com.factset.sdk.utils.exceptions;

public class SigningJwsException extends Exception {
    public SigningJwsException(final String message) {
        super(message);
    }

    public SigningJwsException(final String message, final Exception innerMessage) {
        super(message, innerMessage);
    }
}
