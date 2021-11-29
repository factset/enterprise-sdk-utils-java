package com.factset.sdk.utils.exceptions;

public class ConfigurationException extends Exception {
    public ConfigurationException(final String message, final Exception e) {
        super(message, e);
    }

    public ConfigurationException(final String message) {
        super(message);
    }
}
