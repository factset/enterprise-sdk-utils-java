package com.factset.sdk.utils.authentication;

import com.factset.sdk.utils.exceptions.ConfigurationException;
import com.nimbusds.jose.jwk.RSAKey;
import org.json.JSONArray;
import org.json.JSONObject;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Provides an instance of a validated configuration to be used for creating JWTs.
 */
public class Configuration {

    private final String clientId;
    private final String clientAuthType;
    private final URL wellKnownUrl;
    private final RSAKey jwk;
    private final List<String> scopes;

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
     * @param wellKnownUri   Custom WellKnownUri to retrieve metadata from, about its authorization server. When null,
     *                       FactSet's default well known URI is used.
     * @throws ConfigurationException   If JWK required keys are missing from the RSA or any keys with a value that is
     *                                  null or an empty string.
     * @throws IllegalArgumentException Unchecked exception, if clientID or clientAuthType is null or empty.
     */
    public Configuration(final String clientId,
                         final String clientAuthType,
                         final RSAKey jwk,
                         final String wellKnownUri) throws ConfigurationException {
        this(clientId, clientAuthType, jwk, wellKnownUri, Collections.<String>emptyList());
    }

    /**
     * Creates a valid Configuration instance containing data needed to create a JWT.
     *
     * @param clientId       The Client ID registered with FactSet:Developer.
     * @param clientAuthType The ClientAuthType.
     * @param jwk            The JWK key.
     * @param wellKnownUri   Custom WellKnownUri to retrieve metadata from, about its authorization server. When null,
     *                       FactSet's default well known URI is used.
     * @param scopes         The OAuth 2.0 scopes to request when fetching an access token. Optional; when null or
     *                       empty, the client's default registered scopes are used.
     * @throws ConfigurationException   If JWK required keys are missing from the RSA or any keys with a value that is
     *                                  null or an empty string.
     * @throws IllegalArgumentException Unchecked exception, if clientID or clientAuthType is null or empty, or if any
     *                                  scope is null or empty.
     */
    public Configuration(final String clientId,
                         final String clientAuthType,
                         final RSAKey jwk,
                         final String wellKnownUri,
                         final List<String> scopes) throws ConfigurationException {

        this.clientId = clientId;
        this.clientAuthType = clientAuthType;
        this.jwk = jwk;
        this.scopes = copyScopes(scopes);
        try {
            this.wellKnownUrl = new URL(wellKnownUri == null ? Constants.FACTSET_WELL_KNOWN_URI : wellKnownUri);
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
            this.scopes = parseScopes(jsonObject);
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

    /**
     * The OAuth 2.0 scopes to request when fetching an access token. When empty, the client's default registered
     * scopes are used.
     *
     * @return An unmodifiable list of scopes, never null.
     */
    public List<String> getScopes() {
        return this.scopes;
    }

    private static List<String> parseScopes(final JSONObject jsonObject) {
        if (!jsonObject.has("scopes")) {
            return Collections.emptyList();
        }

        // getJSONArray/getString (rather than the opt* variants) so a malformed "scopes" value fails loudly instead
        // of silently requesting no scopes.
        final JSONArray scopesJson = jsonObject.getJSONArray("scopes");
        final List<String> parsedScopes = new ArrayList<String>(scopesJson.length());
        for (int i = 0; i < scopesJson.length(); i++) {
            parsedScopes.add(scopesJson.getString(i));
        }

        return Collections.unmodifiableList(parsedScopes);
    }

    private static List<String> copyScopes(final List<String> scopes) {
        if (scopes == null || scopes.isEmpty()) {
            return Collections.emptyList();
        }

        return Collections.unmodifiableList(new ArrayList<String>(scopes));
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

        for (final String scope : this.scopes) {
            if (scope == null || scope.trim().isEmpty()) {
                throw new IllegalArgumentException("scopes can not contain null or empty values");
            }
        }
    }
}
