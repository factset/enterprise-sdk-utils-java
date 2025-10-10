package com.factset.sdk.utils.authentication;

import lombok.Builder;
import lombok.Value;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.net.Proxy;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    String userAgent = "fds-sdk/java/utils/1.1.5 (" + System.getProperty("os.name") + "; Java" + System.getProperty("java.version") + ")";

    /**
     * Maximum allowed proactive refresh offset (894 seconds).
     */
    public static final Duration MAX_PROACTIVE_OFFSET = Duration.ofSeconds(894);

    private static final Logger LOG = LoggerFactory.getLogger(RequestOptions.class);

    @Builder.Default
    Duration accessTokenExpiryOffset = Duration.ofSeconds(30);


    public static RequestOptionsBuilder builder() {
        return new RequestOptionsBuilder() {

            @Override
            public RequestOptionsBuilder accessTokenExpiryOffset(Duration d) {
                if (d == null) throw new IllegalArgumentException("accessTokenExpiryOffset cannot be null");
                if (d.compareTo(MAX_PROACTIVE_OFFSET) > 0) {
                    LOG.warn("Configured accessTokenExpiryOffset {} exceeds max {}; clamped to {}.", d, MAX_PROACTIVE_OFFSET, MAX_PROACTIVE_OFFSET);
                    return super.accessTokenExpiryOffset(MAX_PROACTIVE_OFFSET);
                }

                return super.accessTokenExpiryOffset(d);
            }
        };
    }
}
