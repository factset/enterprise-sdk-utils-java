package com.factset.sdk.utils.authentication;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class OAuth2ClientTest {

    @Test
    void oAuth2ClientGoodInstantiation(){
        OAuth2ClientExample oAuth2ClientExample = new OAuth2ClientExample();
        Assertions.assertEquals("testOAuth", oAuth2ClientExample.getAccessToken());
    }

    static class OAuth2ClientExample implements OAuth2Client {
        @Override
        public String getAccessToken() {
            return "testOAuth";
        }
    }
}

