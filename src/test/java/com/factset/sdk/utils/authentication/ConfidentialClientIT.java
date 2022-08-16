package com.factset.sdk.utils.authentication;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.factset.sdk.utils.exceptions.AccessTokenException;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.jose.jwk.RSAKey;
import org.assertj.core.api.ListAssert;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.nio.file.Paths;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static java.nio.file.Files.readAllBytes;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.HamcrestCondition.matching;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertThrows;

@WireMockTest
public class ConfidentialClientIT
{
    private static Configuration configuration = null;

    @BeforeAll
    static void prepare_config(WireMockRuntimeInfo wm) throws Exception
    {
        configuration = new Configuration(
            "testClientId",
            "testAuthType",
            RSAKey.parse(ConfidentialClientTest.validJwk),
            String.format("http://localhost:%d/well-known", wm.getHttpPort()));
    }

    @BeforeEach
    void setup_well_known_url_stub(WireMockRuntimeInfo wm) throws Exception
    {
        String wellKnown = new String(readAllBytes(Paths.get("./src/test/resources/well-known-uri-response.json")))
            .replace("https://example.com", String.format("http://localhost:%d", wm.getHttpPort()));

        stubFor(get("/well-known").willReturn(okJson(wellKnown)));
    }

    @Test
    void logs_request_and_response_for_success()
    {
        stubFor(post("/as/token.oauth2").willReturn(okJson(
            "{\"access_token\":\"xxx_access_token\",\"token_type\":\"Bearer\",\"expires_in\":1234}")));

        assertThatLogs(() -> new ConfidentialClient(configuration).getAccessToken())
            .map(log -> log.getLevel() + ":" + log.getFormattedMessage())
            .haveAtLeastOne(matching(startsWith("TRACE:Token Request: POST")))
            .haveAtLeastOne(matching(startsWith("TRACE:Token Response: 200 OK")));
    }

    @Test
    void logs_request_and_response_for_error()
    {
        stubFor(post("/as/token.oauth2").willReturn(badRequest()));

        assertThatLogs(AccessTokenException.class, () -> new ConfidentialClient(configuration).getAccessToken())
            .map(log -> log.getLevel() + ":" + log.getFormattedMessage())
            .haveAtLeastOne(matching(startsWith("TRACE:Token Request: POST")))
            .haveAtLeastOne(matching(startsWith("TRACE:Token Response: 400 Bad Request")));
    }

    private static ListAssert<ILoggingEvent> assertThatLogs(ThrowingRunnable test)
    {
        // get a handle to the underlying logger
        // and add our own appender to it to intercept logs
        LoggerContext lc = (LoggerContext)LoggerFactory.getILoggerFactory();
        Logger logger = lc.getLogger(ConfidentialClient.class);

        // fortunately Logback already comes with a simple appender
        // that just adds logs to a list.
        ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
        listAppender.setContext(lc);
        listAppender.start();

        Level previousLevel = logger.getLevel();
        logger.addAppender(listAppender);
        logger.setLevel(Level.TRACE);

        try {
            test.run();
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            logger.detachAppender(listAppender);
            logger.setLevel(previousLevel);
            listAppender.stop();
        }

        return assertThat(listAppender.list);
    }

    private static <T extends Throwable> ListAssert<ILoggingEvent> assertThatLogs(
        Class<T> expectedException, ThrowingRunnable test)
    {
        return assertThatLogs(() -> assertThrows(expectedException, test::run));
    }

    interface ThrowingRunnable
    {
        void run() throws Exception;
    }

}
