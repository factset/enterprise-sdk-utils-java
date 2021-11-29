package com.factset.sdk.utils.exceptions;

public class AuthServerMetadataException extends Exception {

    public AuthServerMetadataException(final String message, final Exception e) {
        super(message, e);
    }
}
