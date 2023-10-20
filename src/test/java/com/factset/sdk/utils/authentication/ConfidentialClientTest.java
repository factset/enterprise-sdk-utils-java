package com.factset.sdk.utils.authentication;

import com.factset.sdk.utils.exceptions.*;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ConfidentialClientTest {

    public final static String validJwk = "{\n" +
        "    \"p\": \"3QAUkyFNCv8CRLQfpj9zovNUchcN-HgCxOY_BMWPsbFzZ8slliFoQl8EANEJJPUMKY8sh3ZnU0pH2T8qoQoRvDstX4XzH0kdMKK8LMJ-8J5Nzf2Ps9Z2va_G0OhkMkdT__7jzO-qHQAgIxOy15ka4JGvqhi9fsB13RslsRNOpnk\",\n" +
        "    \"kty\": \"RSA\",\n" +
        "    \"q\": \"oBZ17ZrK2B5ufELRwc3ZLB09xo2LjuEK7k8ZTtM5FUBTn-6hoaJwwyJvI5UgxY5Ge46i_wQifMOJb3g-ALu8pq-Nm6N0HmZ9dxU8_REZEQFARM9pieU-dQxYJZFrbqWFLiVYc8kq8mocQe25TFmBI3t_TQ8Y7C2KltOKQTbnkAs\",\n" +
        "    \"d\": \"eeZ7uLCCq9Xzd6q0O13F38hfGEgajV_zMf893Bm-qjH3ipzwCztESeqaKJFNmZEkQ1a2ee2Rvjt0yZLF-8Fxu53TgfEipNWF03zraEhmM62wf86g1dFrAwFBJ0-HbPyQ_Z9zvD8y_XjrxNJ887bxHJmnFU1ER2AfW519mHm2zH8mU_tZQrhQ3f8bJSkg528LDSmStCXUPHKczxdCQj5Vg93mZQtHFG-r3h0AHWZKIidDqoFZTNuimrFL-BTAiT72GnFDhJTKpzGnWXeQ65e_0z0agh2hHYTNyKcTffWjRnNwH5q02VpHLHQ_I8GFGmhzdN4Mtg9tVQ_dpOiOiaw-UQ\",\n" +
        "    \"e\": \"AQAB\",\n" +
        "    \"use\": \"sig\",\n" +
        "    \"kid\": \"Pa-A4WppSTO39nfRFBP_IpM13sBNXnmj9liYF5pYRhI\",\n" +
        "    \"qi\": \"tBOoQVBu032Lkpnv5z5I4ynNhW8wD5o8DzMyH6OOeFujTz83plsk8zwZiKnSKcL2Qx9eUgmcLGMlx30lkyaw0nkHB7P6WDXqXsrS1c69ninzkzHd32-tQpqrOMT8vQKa0tawZjrIaEoR-3MhbMOXYrNCZvuixdJXz2E4KrJsFN0\",\n" +
        "    \"dp\": \"tbb-M-ga0CLUO6ebqnfb3i2Tzuez_gy3wizLvmGvgF03Vi3MbwBzGLfFs-ItUa0H3hgydgPee7bFExWEOLvtz0cdTMD4Ik5c6QO2FFusQq73rJuEEEwUgG3K3TVoRYsuv3xW1MhvqL7UreLhl7L1TZecyBDlpxYbE73hpRMKBYk\",\n" +
        "    \"alg\": \"RS256\",\n" +
        "    \"dq\": \"QzGqRhUW1yfO0DFrwaEZar7LUy_OSCaFZAmnYcKezyC0-Qg8p497LSyi4ZiSrNlPFEWGfOvLXfrlEPizbbNfN8ev9IfjEW-LchRkCQTINK8FvtwgPFUQpiiMRxiGs2aeRARA4Dir4hxPyAx0HmvjHHWVtU6E830aEryv5zeYcok\",\n" +
        "    \"n\": \"ijNwq-GQdu9yj1fpCLF3LJeKD_KxCFdVR6s4N57eNuhfZKGwQrnc_kf_1j7VLPCHx-UVI-S4A2yUKlo-G6h2otpQUtoN9WYaSIrowo2k7Fdd55zW1rtNzD_XplWLc8ZnBrGHLfWAQfMDHvhHsuPVctt3uH1aIv768iWahALra-ym0HHge_mluCD823Ovam-q_sn50ZCf58DbecZj7VGVCkzRNLDJsnSvh3w7BHDwUhw_oZls75IfZ-ORZQuykfEDvaHCrNbHaKJFK843m9v5C47BGqjTEqBOQ71XR3oZ-Znr1nlcE8k1FlkgA3VCFWFZuixEQJtg1tiKqbtGzzQ3Mw\"\n" +
        "}";

    private static Path pathToResources;

    @BeforeAll
    static void setup() {
        pathToResources = Paths.get(System.getProperty("user.dir"), "src", "test", "resources");
    }

    @Test
    void confidentialClientNullConfigThrowsNullPointerException() {
        try {
            new ConfidentialClient((Configuration) null);
            fail();
        } catch (Exception e) {
            assertTrue(e instanceof NullPointerException);
            assertEquals("Configuration object must not be null", e.getMessage());
        }
    }

    @Test
    void confidentialClientInvalidPathThrowsConfigurationException() {
        try {
            new ConfidentialClient("invalid/path");
            fail();
        } catch (Exception e) {
            assertTrue(e instanceof ConfigurationException);
        }
    }

    @Test
    void confidentialClientNullConfigPathThrowsConfigurationException() {
        try {
            new ConfidentialClient((String) null);
            fail();
        } catch (Exception e) {
            assertTrue(e instanceof ConfigurationException);
            assertEquals("Exception caught when retrieving contents from file", e.getMessage());
        }
    }

    @Test
    void confidentialClientValidPathEmptyConfigThrowsConfigurationException() {
        try {
            new ConfidentialClient(String.valueOf(Paths.get(pathToResources.toString(), "emptyJson.txt")));
            fail();
        } catch (Exception e) {
            assertTrue(e instanceof ConfigurationException);
            assertEquals("Exception caught when retrieving contents from file", e.getMessage());
        }
    }

    @Test
    void confidentialClientValidPathEmptyFieldsThrowsConfigurationException() {
        try {
            new ConfidentialClient(String.valueOf(Paths.get(pathToResources.toString(), "emptyValues.txt")));
            fail();
        } catch (Exception e) {
            assertTrue(e instanceof ConfigurationException);
            assertEquals("Exception caught when retrieving contents from file", e.getMessage());
        }
    }

    @Test
    void confidentialClientValidPathMissingFieldsThrowsConfigurationException() {
        try {
            new ConfidentialClient(String.valueOf(Paths.get(pathToResources.toString(), "missingValues.txt")));
            fail();
        } catch (Exception e) {
            assertTrue(e instanceof ConfigurationException);
            assertEquals("Exception caught when retrieving contents from file", e.getMessage());
        }
    }

    @Test
    void confidentialClientValidPathValidConfigCannotOpenConnectionThrowsAuthServerMetadataException() {
        try {
            new ConfidentialClient(getConfigSpyThrowsIOException("validConfig.txt"));
            fail();
        } catch (Exception e) {
            assertTrue(e instanceof AuthServerMetadataException);
            assertEquals("Error retrieving contents from WellKnownUri: " + Constants.FACTSET_WELL_KNOWN_URI,
                    e.getMessage());
        }
    }

    @Test
    void confidentialClientValidPathValidConfigCustomWellKnownUriThrowsConfigurationException() {
        try {
            Configuration configuration = new Configuration("testClientId",
                                                            "testAuthType",
                                                            RSAKey.parse(validJwk),
                                                            "failing:wellKnownUri//");

            new ConfidentialClient(configuration);
            fail();
        } catch (Exception e) {
            assertTrue(e instanceof ConfigurationException);
        }
    }

    @Test
    void confidentialClientValidPathValidConfigCannotGetInputStreamThrowsAuthServerMetadataException() {
        try {
            new ConfidentialClient(getConfigSpyThrowsIOException("validConfig.txt"));
            fail();
        } catch (Exception e) {
            assertTrue(e instanceof AuthServerMetadataException);
            assertEquals(String.format("Error retrieving contents from WellKnownUri: %s", Constants.FACTSET_WELL_KNOWN_URI),
                         e.getMessage());
        }
    }

    @Test
    void confidentialClientValidPathValidConfigMissingIssuerAndTokenEndpointThrowsAuthServerMetadataContentException() {
        assertThrows(AuthServerMetadataContentException.class,
                () -> new ConfidentialClient(getConfigSpyMockedResponse("emptyJson.txt", "validConfig.txt")));
    }

    @Test
    void confidentialClientValidPathValidConfigCustomWellKnownUriInitialisesWithNoException() {
        assertDoesNotThrow(() -> {
            Configuration configuration = new Configuration("testClientId",
                "testAuthType",
                RSAKey.parse(validJwk),
                "https://test.test.com/.test-test/test-test");

            // If this confidential client is instantiated without exceptions, that results in a passing test.
            URL mockedURL = getUrlMockResponse("exampleResponseWellKnownUri.txt");
            Configuration configurationSpy = spy(configuration);
            when(configurationSpy.getWellKnownUrl()).thenReturn(mockedURL);
            new ConfidentialClient(configurationSpy);
        });
    }

    @Test
    void confidentialClientValidConfigInitialisesWithNoException() {
        assertDoesNotThrow(() -> {
            // If this confidential client is instantiated without exceptions, that results in a passing test.
            new ConfidentialClient(getConfigSpyMockedResponse("exampleResponseWellKnownUri.txt", "validConfig.txt"));
        });
    }

    @Test
    void getAccessTokenCallingWithFailedSigningRaisesSigningJwsException() throws Exception {
        try {
            ConfidentialClient confidentialClient = new ConfidentialClient(String.valueOf(Paths.get(
                    pathToResources.toString(),
                    "validConfigStructure.txt"
            )));
            confidentialClient.getAccessToken();
            fail();
        } catch (SigningJwsException e) {
            assertEquals("Unable to create signer", e.getMessage());
        }
    }

    @Test
    void getAccessTokenCallingWithErroneousResponseRaisesAccessTokenException() throws Exception {
        try {
            Configuration configurationMock = ConfidentialClientTest.getConfigSpyMockedResponse(
                    "exampleResponseWellKnownUri.txt", "validConfig.txt"
            );

            TokenRequestBuilder tokenRequestBuilderSpy = ConfidentialClientTest.createTokenRequestBuilderSpy(
                    HTTPResponse.SC_UNAUTHORIZED,
                    "{\"error_description\":\"Unauthorized access.\",\"error\":\"invalid_request\"}",
                    false
            );

            ConfidentialClient confidentialClientSpy = spy(new ConfidentialClient(configurationMock, tokenRequestBuilderSpy));
            confidentialClientSpy.getAccessToken();
            fail();
        } catch (AccessTokenException e) {
            assertEquals("Unsuccessful token response: Failed to authenticate or parse the token", e.getMessage());
        }
    }

    @Test
    void getAccessTokenCalledForTheFirstTimeReturnsANewAccessToken() throws Exception {
        Configuration configurationMock = ConfidentialClientTest.getConfigSpyMockedResponse(
                "exampleResponseWellKnownUri.txt", "validConfig.txt"
        );

        TokenRequestBuilder tokenRequestBuilderSpy = ConfidentialClientTest.createTokenRequestBuilderSpy(
                HTTPResponse.SC_OK,
                "{\"access_token\":\"test token\",\"token_type\":\"Bearer\",\"expires_in\":899}",
                true
        );

        ConfidentialClient confidentialClientSpy = spy(new ConfidentialClient(configurationMock, tokenRequestBuilderSpy));
        String accessToken = confidentialClientSpy.getAccessToken();

        assertEquals("test token", accessToken);
    }

    @Test
    void getAccessTokenCalledTwiceBeforeExpirationReturnsSameAccessToken() throws Exception {
        Configuration configurationMock = ConfidentialClientTest.getConfigSpyMockedResponse(
                "exampleResponseWellKnownUri.txt", "validConfig.txt"
        );

        HTTPResponse res = new HTTPResponse(HTTPResponse.SC_OK);
        res.setContent("{\"access_token\":\"test token\",\"token_type\":\"Bearer\",\"expires_in\":899}");
        res.setHeader("Content-Type", "application/json;charset=utf-8");

        AuthorizationGrant grant = new UnitTestGrant();
        URI uriSpy = spy(new URI("https://test.test.com/.test-test/test-test"));
        TokenRequest tokenRequestMock = spy(new TokenRequest(uriSpy, grant, new Scope()));

        TokenRequestBuilder tokenRequestBuilderSpy = spy(new TokenRequestBuilder());

        HTTPRequest httpRequestMock = mock(HTTPRequest.class);

        doReturn(tokenRequestMock).when(tokenRequestBuilderSpy).build();
        doReturn(httpRequestMock).when(tokenRequestMock).toHTTPRequest();
        doReturn(res).when(httpRequestMock).send();

        ConfidentialClient confidentialClientSpy = spy(new ConfidentialClient(configurationMock, tokenRequestBuilderSpy));

        String accessToken1 = confidentialClientSpy.getAccessToken();
        String accessToken2 = confidentialClientSpy.getAccessToken();

        assertEquals("test token", accessToken1);
        assertEquals("test token", accessToken2);
        verify(httpRequestMock).send();
    }

    @Test
    void getAccessTokenCallingBeforeAndAfterExpirationReturnsDifferentAccessToken() throws Exception {
        Configuration configurationMock = ConfidentialClientTest.getConfigSpyMockedResponse(
                "exampleResponseWellKnownUri.txt", "validConfig.txt"
        );

        HTTPResponse res1 = new HTTPResponse(HTTPResponse.SC_OK);
        res1.setContent("{\"access_token\":\"test token 1\",\"token_type\":\"Bearer\",\"expires_in\":0}");
        res1.setHeader("Content-Type", "application/json;charset=utf-8");

        HTTPResponse res2 = new HTTPResponse(HTTPResponse.SC_OK);
        res2.setContent("{\"access_token\":\"test token 2\",\"token_type\":\"Bearer\",\"expires_in\":0}");
        res2.setHeader("Content-Type", "application/json;charset=utf-8");

        AuthorizationGrant grant = new UnitTestGrant();
        URI uriSpy = spy(new URI("https://test.test.com/.test-test/test-test"));
        TokenRequest tokenRequestMock = spy(new TokenRequest(uriSpy, grant, new Scope()));

        TokenRequestBuilder tokenRequestBuilderSpy = spy(new TokenRequestBuilder());

        HTTPRequest httpRequestMock = mock(HTTPRequest.class);

        doReturn(tokenRequestMock).when(tokenRequestBuilderSpy).build();
        doReturn(httpRequestMock).when(tokenRequestMock).toHTTPRequest();
        doReturn(res1).doReturn(res2).when(httpRequestMock).send();

        ConfidentialClient confidentialClientSpy = spy(new ConfidentialClient(configurationMock, tokenRequestBuilderSpy));

        String accessToken1 = confidentialClientSpy.getAccessToken();
        String accessToken2 = confidentialClientSpy.getAccessToken();

        assertEquals("test token 1", accessToken1);
        assertEquals("test token 2", accessToken2);
        verify(httpRequestMock, times(2)).send();
    }

    @Test
    void getAccessTokenCallingWithSendErrorRaisesAccessTokenException() throws Exception {
        try {
            Configuration configurationMock = ConfidentialClientTest.getConfigSpyMockedResponse(
                    "exampleResponseWellKnownUri.txt", "validConfig.txt"
            );

            TokenRequestBuilder tokenRequestBuilderSpy = ConfidentialClientTest.createTokenRequestBuilderSpy(
                    HTTPResponse.SC_OK,
                    "{\"error_description\":\"Invalid request.\",\"error\":\"invalid_request\"}",
                    false
            );

            ConfidentialClient confidentialClientSpy = spy(new ConfidentialClient(configurationMock, tokenRequestBuilderSpy));

            confidentialClientSpy.getAccessToken();
            fail();
        } catch (AccessTokenException e) {
            assertEquals("Error attempting to get the access token", e.getMessage());
        }
    }

    private static URL getUrlMockResponse(String stringFile) throws IOException {
        final File file = new File(String.valueOf(Paths.get(String.valueOf(pathToResources), stringFile)));

        URL mockedUrl = mock(URL.class);
        HttpURLConnection mockedConn = mock(HttpURLConnection.class);
        when(mockedUrl.openConnection(any(Proxy.class))).thenReturn(mockedConn);
        when(mockedConn.getInputStream()).thenReturn(Files.newInputStream(file.toPath()));

        return mockedUrl;
    }

    private static Configuration getConfigSpyMockedResponse(String urlResponse, String configFile) throws IOException, ConfigurationException {
        URL mockedURL = getUrlMockResponse(urlResponse);
        Configuration configuration = new Configuration(String.valueOf(Paths.get(pathToResources.toString(), configFile)));
        Configuration configurationSpy = spy(configuration);
        when(configurationSpy.getWellKnownUrl()).thenReturn(mockedURL);

        return configurationSpy;
    }

    private static Configuration getConfigSpyThrowsIOException(String configFile) throws IOException, ConfigurationException {
        URL mockedUrl = mock(URL.class);
        when(mockedUrl.openConnection(any(Proxy.class))).thenThrow(IOException.class);
        Configuration configuration = new Configuration(String.valueOf(Paths.get(pathToResources.toString(), configFile)));
        Configuration configurationSpy = spy(configuration);
        when(configurationSpy.getWellKnownUrl()).thenReturn(mockedUrl).thenCallRealMethod();

        return configurationSpy;
    }

    private static TokenRequestBuilder createTokenRequestBuilderSpy(int statusCode, String resContent,
                                                                    boolean requiresHeader) throws URISyntaxException,
                                                                                                   IOException {
        HTTPResponse res = new HTTPResponse(statusCode);
        res.setContent(resContent);
        if (requiresHeader) {
            res.setHeader("Content-Type", "application/json;charset=utf-8");
        }

        AuthorizationGrant grant = new UnitTestGrant();

        URI uriSpy = spy(new URI("https://test.test.com/.test-test/test-test"));
        TokenRequest tokenRequestMock = spy(new TokenRequest(uriSpy, grant, new Scope()));

        TokenRequestBuilder tokenRequestBuilderSpy = spy(new TokenRequestBuilder());

        HTTPRequest httpRequestMock = mock(HTTPRequest.class);

        doReturn(tokenRequestMock).when(tokenRequestBuilderSpy).build();
        doReturn(httpRequestMock).when(tokenRequestMock).toHTTPRequest();
        doReturn(res).when(httpRequestMock).send();

        return tokenRequestBuilderSpy;
    }

    private static class UnitTestGrant extends AuthorizationGrant {

        /**
         * Creates a new custom authorisation grant used for mock testing purposes which makes use of GrantType.REFRESH_TOKEN
         * which does not require any parameter setup such as the GrantType.CLIENT_CREDENTIALS.
         */
        protected UnitTestGrant() {
            super(GrantType.REFRESH_TOKEN);
        }

        @Override
        public Map<String, List<String>> toParameters() {
            return null;
        }
    }
}
