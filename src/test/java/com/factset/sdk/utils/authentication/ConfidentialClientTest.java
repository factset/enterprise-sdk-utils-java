package com.factset.sdk.utils.authentication;

import com.factset.sdk.utils.exceptions.*;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.OngoingStubbing;

import javax.net.ssl.HttpsURLConnection;
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
    void confidentialClientValidPathValidConfigMissingIssuerAndTokenEndpointThrowsAuthServerMetadataContentException() throws Exception {
        HttpURLConnection mockedConn = mock(HttpURLConnection.class);
        URL mockedURL = getUrlMockResponse("emptyJson.txt", mockedConn);
        assertThrows(AuthServerMetadataContentException.class,
                () -> new ConfidentialClient(getConfigSpyMockedResponse(mockedURL, "validConfig.txt")));
    }

    @Test
    void confidentialClientValidPathValidConfigCustomWellKnownUriInitialisesWithNoException() {
        assertDoesNotThrow(() -> {
            Configuration configuration = new Configuration("testClientId",
                "testAuthType",
                RSAKey.parse(validJwk),
                "https://test.test.com/.test-test/test-test");

            // If this confidential client is instantiated without exceptions, that results in a passing test.
            HttpURLConnection mockedConn = mock(HttpURLConnection.class);
            URL mockedURL = getUrlMockResponse("exampleResponseWellKnownUri.txt", mockedConn);
            Configuration configurationSpy = spy(configuration);
            when(configurationSpy.getWellKnownUrl()).thenReturn(mockedURL);
            new ConfidentialClient(configurationSpy);
        });
    }

    @Test
    void confidentialClientValidConfigInitialisesWithNoException() {
        assertDoesNotThrow(() -> {
            // If this confidential client is instantiated without exceptions, that results in a passing test.
            HttpURLConnection mockedConn = mock(HttpURLConnection.class);
            URL mockedURL = getUrlMockResponse("exampleResponseWellKnownUri.txt", mockedConn);
            new ConfidentialClient(getConfigSpyMockedResponse(mockedURL, "validConfig.txt"));
        });
    }

    @Test
    void confidentialClientValidConfigInitialisesWithRequestOptions() throws Exception {
        Proxy mockProxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 8080));
        RequestOptions reqOptions = RequestOptions.builder().proxy(mockProxy).build();

        HttpsURLConnection mockedConn = mock(HttpsURLConnection.class);
        URL mockedURL = getUrlMockResponse("exampleResponseWellKnownUri.txt", mockedConn);
        Configuration config = getConfigSpyMockedResponse(mockedURL, "validConfig.txt");
        new ConfidentialClient(config, reqOptions);

        verify(mockedURL).openConnection(mockProxy);
        verify(mockedConn).setHostnameVerifier(reqOptions.getHostnameVerifier());
        verify(mockedConn).setSSLSocketFactory(reqOptions.getSslSocketFactory());
    }

    @Test
    void confidentialClientValidConfigInitialisesWithRequestOptionsAsNull() throws Exception {
        HttpsURLConnection mockedConn = mock(HttpsURLConnection.class);
        URL mockedURL = getUrlMockResponse("exampleResponseWellKnownUri.txt", mockedConn);
        Configuration config = getConfigSpyMockedResponse(mockedURL, "validConfig.txt");
        RequestOptions reqOpts = null;
        new ConfidentialClient(config, reqOpts);

        verify(mockedURL).openConnection(Proxy.NO_PROXY);
        verify(mockedConn).setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());
        verify(mockedConn).setSSLSocketFactory(HttpsURLConnection.getDefaultSSLSocketFactory());
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
            HttpURLConnection mockedConn = mock(HttpURLConnection.class);
            URL mockedURL = getUrlMockResponse("exampleResponseWellKnownUri.txt", mockedConn);
            Configuration configurationMock = ConfidentialClientTest.getConfigSpyMockedResponse(
                    mockedURL, "validConfig.txt"
            );

            HTTPRequest mockedRequest = mock(HTTPRequest.class);
            TokenRequestBuilder tokenRequestBuilderSpy = ConfidentialClientTest.createTokenRequestBuilderSpy(
                    HTTPResponse.SC_UNAUTHORIZED,
                    "{\"error_description\":\"Unauthorized access.\",\"error\":\"invalid_request\"}",
                    false,
                    mockedRequest
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
        TestHarness harness = createClientWithTokens(899, "test token");
        String accessToken = harness.client.getAccessToken();
        assertEquals("test token", accessToken);
        verify(harness.httpRequestMock, times(1)).send();
    }

    @Test
    void getAccessTokenCalledWithRequestOptionsSetsProxyAndSSLSettings() throws Exception {
        HttpURLConnection mockedConn = mock(HttpURLConnection.class);
        URL mockedURL = getUrlMockResponse("exampleResponseWellKnownUri.txt", mockedConn);
        Configuration configurationMock = ConfidentialClientTest.getConfigSpyMockedResponse(
                mockedURL, "validConfig.txt"
        );

        HTTPRequest mockedRequest = mock(HTTPRequest.class);
        TokenRequestBuilder tokenRequestBuilderSpy = ConfidentialClientTest.createTokenRequestBuilderSpy(
                HTTPResponse.SC_OK,
                "{\"access_token\":\"test token\",\"token_type\":\"Bearer\",\"expires_in\":899}",
                true,
                mockedRequest
        );

        Proxy mockProxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 8080));
        RequestOptions reqOptions = RequestOptions.builder().proxy(mockProxy).build();
        ConfidentialClient confidentialClientSpy = spy(new ConfidentialClient(configurationMock, tokenRequestBuilderSpy, reqOptions));
        confidentialClientSpy.getAccessToken();

        verify(mockedRequest).setProxy(mockProxy);
        verify(mockedRequest).setHostnameVerifier(reqOptions.getHostnameVerifier());
        verify(mockedRequest).setSSLSocketFactory(reqOptions.getSslSocketFactory());
    }

    @Test
    void getAccessTokenCalledTwiceBeforeExpirationReturnsSameAccessToken() throws Exception {
        TestHarness harness = createClientWithTokens(899, "test token");
        String accessToken1 = harness.client.getAccessToken();
        String accessToken2 = harness.client.getAccessToken();
        assertEquals("test token", accessToken1);
        assertEquals("test token", accessToken2);
        verify(harness.httpRequestMock, times(1)).send();
    }

    @Test
    void getAccessTokenCallingBeforeAndAfterExpirationReturnsDifferentAccessToken() throws Exception {
        TestHarness harness = createClientWithTokens(0, "test token 1", "test token 2");
        String accessToken1 = harness.client.getAccessToken();
        String accessToken2 = harness.client.getAccessToken();
        assertEquals("test token 1", accessToken1);
        assertEquals("test token 2", accessToken2);
        verify(harness.httpRequestMock, times(2)).send();
    }

    @Test
    void getAccessTokenWithForceRefreshTrueAlwaysFetchesNewToken() throws Exception {
        TestHarness harness = createClientWithTokens(899, "token1", "token2");
        String tokenA = harness.client.getAccessToken(true);
        String tokenB = harness.client.getAccessToken(true);
        assertEquals("token1", tokenA);
        assertEquals("token2", tokenB);
        verify(harness.httpRequestMock, times(2)).send();
    }

    @Test
    void getAccessTokenWithForceRefreshFalseReturnsCachedTokenIfValid() throws Exception {
        TestHarness harness = createClientWithTokens(899, "tokenX");
        String token1 = harness.client.getAccessToken(false);
        String token2 = harness.client.getAccessToken(false);
        assertEquals("tokenX", token1);
        assertEquals("tokenX", token2);
        verify(harness.httpRequestMock, times(1)).send();
    }

    @Test
    void getAccessTokenForceRefreshThenCachedReturnsCorrectTokens() throws Exception {
        TestHarness harness = createClientWithTokens(899, "tokenA", "tokenB");
        String tokenA = harness.client.getAccessToken(true); // force fetch first (tokenA)
        String tokenB = harness.client.getAccessToken(false); // should use cached tokenA, not fetch tokenB
        assertEquals("tokenA", tokenA);
        assertEquals("tokenA", tokenB);
        verify(harness.httpRequestMock, times(1)).send();
    }

    private static class TestHarness {
        final ConfidentialClient client;
        final HTTPRequest httpRequestMock;
        TestHarness(ConfidentialClient client, HTTPRequest httpRequestMock) {
            this.client = client;
            this.httpRequestMock = httpRequestMock;
        }
    }

    private static TestHarness createClientWithTokens(int expiresInSeconds, String... tokens) throws Exception {
        HttpURLConnection mockedConn = mock(HttpURLConnection.class);
        URL mockedURL = getUrlMockResponse("exampleResponseWellKnownUri.txt", mockedConn);
        Configuration configurationMock = getConfigSpyMockedResponse(mockedURL, "validConfig.txt");

        AuthorizationGrant grant = new UnitTestGrant();
        URI uriSpy = spy(new URI("https://test.test.com/.test-test/test-test"));
        TokenRequest tokenRequestMock = spy(new TokenRequest(uriSpy, grant, new Scope()));
        TokenRequestBuilder tokenRequestBuilderSpy = spy(new TokenRequestBuilder());
        HTTPRequest httpRequestMock = mock(HTTPRequest.class);

        OngoingStubbing<HTTPResponse> stubbing = null;
        for (String token : tokens) {
            HTTPResponse res = new HTTPResponse(HTTPResponse.SC_OK);
            String body = String.format("{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":%d}", token, expiresInSeconds);
            res.setContent(body);
            res.setHeader("Content-Type", "application/json;charset=utf-8");
            if (stubbing == null) {
                stubbing = when(httpRequestMock.send());
                stubbing = stubbing.thenReturn(res);
            } else {
                stubbing = stubbing.thenReturn(res);
            }
        }

        doReturn(tokenRequestMock).when(tokenRequestBuilderSpy).build();
        doReturn(httpRequestMock).when(tokenRequestMock).toHTTPRequest();

        ConfidentialClient confidentialClientSpy = spy(new ConfidentialClient(configurationMock, tokenRequestBuilderSpy));
        return new TestHarness(confidentialClientSpy, httpRequestMock);
    }

    private static URL getUrlMockResponse(String stringFile, HttpURLConnection mockedConn) throws IOException {
        final File file = new File(String.valueOf(Paths.get(String.valueOf(pathToResources), stringFile)));

        URL mockedUrl = mock(URL.class);
        when(mockedUrl.openConnection(any(Proxy.class))).thenReturn(mockedConn);
        when(mockedConn.getInputStream()).thenReturn(Files.newInputStream(file.toPath()));

        return mockedUrl;
    }

    private static Configuration getConfigSpyMockedResponse(URL mockedURL, String configFile) throws ConfigurationException {
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
                                                                    boolean requiresHeader, HTTPRequest mockedRequest) throws URISyntaxException,
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

        doReturn(tokenRequestMock).when(tokenRequestBuilderSpy).build();
        doReturn(mockedRequest).when(tokenRequestMock).toHTTPRequest();
        doReturn(res).when(mockedRequest).send();

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
