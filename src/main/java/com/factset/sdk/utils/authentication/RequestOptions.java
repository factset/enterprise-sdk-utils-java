package com.factset.sdk.utils.authentication;

import lombok.Builder;
import lombok.Value;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.net.Proxy;

@Value
@Builder
public class RequestOptions {
    @Builder.Default
    Proxy proxy = Proxy.NO_PROXY;

    @Builder.Default
    HostnameVerifier hostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();

    @Builder.Default
    SSLSocketFactory sslSocketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();

    @Builder.Default
    String userAgent = "fds-sdk/java/utils/1.1.4 (" + System.getProperty("os.name") + "; Java" + System.getProperty("java.version") + ")";
}
