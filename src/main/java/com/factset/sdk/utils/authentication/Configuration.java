package com.factset.sdk.utils.authentication;

import com.factset.sdk.utils.exceptions.ConfigurationException;
import com.nimbusds.jose.jwk.RSAKey;
import org.json.JSONObject;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Provides an instance of a validated configuration to be used for creating JWTs.
 */
public class Configuration {

    private final String clientId;
    private final String clientAuthType;
    private final URL wellKnownUrl;
    private final RSAKey jwk;

    /**
     * Creates a valid Configuration instance containing data needed to create a JWT.
     *
     * @param clientId       The Client ID registered with FactSet:Developer.
     * @param clientAuthType The ClientAuthType.
     * @param jwk            The JWK key.
     * @throws ConfigurationException   If JWK required keys are missing from the RSA or any keys with a value that is
     *                                  null or an empty string.
     * @throws IllegalArgumentException Unchecked exception, if clientID or clientAuthType is null or empty.
     */
    public Configuration(final String clientId,
                         final String clientAuthType,
                         final RSAKey jwk) throws ConfigurationException {
        this(clientId, clientAuthType, jwk, Constants.FACTSET_WELL_KNOWN_URI);
    }

    /**
     * Creates a valid Configuration instance containing data needed to create a JWT.
     *
     * @param clientId       The Client ID registered with FactSet:Developer.
     * @param clientAuthType The ClientAuthType.
     * @param jwk            The JWK key.
     * @param wellKnownUri   Custom WellKnownUri to retrieve metadata from, about its authorization server.
     * @throws ConfigurationException   If JWK required keys are missing from the RSA or any keys with a value that is
     *                                  null or an empty string.
     * @throws IllegalArgumentException Unchecked exception, if clientID or clientAuthType is null or empty.
     */
    public Configuration(final String clientId,
                         final String clientAuthType,
                         final RSAKey jwk,
                         final String wellKnownUri) throws ConfigurationException {

        this.clientId = clientId;
        this.clientAuthType = clientAuthType;
        this.jwk = jwk;
        try {
            this.wellKnownUrl = new URL(wellKnownUri);
        } catch (final MalformedURLException e) {
            throw new ConfigurationException("Invalid well known URI", e);
        }

        this.checkConfig();
    }

    /**
     * Creates a valid Configuration instance by taking the path to a file containing the configuration in a JSON format
     * and converts it to a Configuration object, if the key value pairs in the JSON are valid (contains required
     * key pairs).
     *
     * @param configPath The path to the file containing the configuration.
     * @throws ConfigurationException   If JWK required keys are missing from the RSA or any keys with a value that is
     *                                  null or an empty string.
     * @throws IllegalArgumentException Unchecked exception, if clientID or clientAuthType is null or empty.
     */
    public Configuration(final String configPath) throws ConfigurationException {
        try {
            final JSONObject jsonObject = new JSONObject(new String(Files.readAllBytes(Paths.get(configPath))));
            this.clientId = jsonObject.getString("clientId");
            this.clientAuthType = jsonObject.getString("clientAuthType");
            this.jwk = RSAKey.parse(jsonObject.getJSONObject("jwk").toString());
            this.wellKnownUrl = new URL(jsonObject.optString("wellKnownUri", Constants.FACTSET_WELL_KNOWN_URI));
        } catch (final Exception e) {
            throw new ConfigurationException("Exception caught when retrieving contents from file", e);
        }

        this.checkConfig();
    }

    /**
     * The Client ID registered with FactSet's Developer Portal.
     *
     * @return A string containing the client ID.
     */
    public String getClientId() {
        return this.clientId;
    }

    /**
     * The ClientAuthType.
     *
     * @return A string containing the client authentication type.
     */
    public String getClientAuthType() {
        return this.clientAuthType;
    }

    /**
     * The Well Known URI.
     *
     * @return A URL instance containing the well known URI.
     */
    public URL getWellKnownUrl() {
        return this.wellKnownUrl;
    }

    /**
     * The JWK.
     *
     * @return An RSAKey object.
     */
    public RSAKey getJwk() {
        return this.jwk;
    }

    private void checkConfig() throws ConfigurationException {
        if (this.clientId == null || this.clientId.isEmpty()) {
            throw new IllegalArgumentException("clientId can not be null or empty");
        }

        if (this.clientAuthType == null || this.clientAuthType.isEmpty()) {
            throw new IllegalArgumentException("clientAuthType can not be null or empty");
        }

        if (this.jwk == null || !this.jwk.isPrivate()) {
            throw new ConfigurationException("JWK can not be null or have missing private key");
        }
    }
}
