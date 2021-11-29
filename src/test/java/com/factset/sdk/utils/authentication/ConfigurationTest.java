package com.factset.sdk.utils.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.factset.sdk.utils.exceptions.ConfigurationException;
import com.nimbusds.jose.jwk.RSAKey;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class ConfigurationTest {

    private static String validJwk;
    private static String invalidJwkMissingKty;
    private static String invalidJwkEmptyKty;
    private static Path pathToResources;

    @BeforeAll
    static void setup() {
        validJwk = "{\n" +
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

        invalidJwkMissingKty = "{\n" +
            "    \"p\": \"3QAUkyFNCv8CRLQfpj9zovNUchcN-HgCxOY_BMWPsbFzZ8slliFoQl8EANEJJPUMKY8sh3ZnU0pH2T8qoQoRvDstX4XzH0kdMKK8LMJ-8J5Nzf2Ps9Z2va_G0OhkMkdT__7jzO-qHQAgIxOy15ka4JGvqhi9fsB13RslsRNOpnk\",\n" +
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

        invalidJwkEmptyKty = "{\n" +
            "    \"p\": \"3QAUkyFNCv8CRLQfpj9zovNUchcN-HgCxOY_BMWPsbFzZ8slliFoQl8EANEJJPUMKY8sh3ZnU0pH2T8qoQoRvDstX4XzH0kdMKK8LMJ-8J5Nzf2Ps9Z2va_G0OhkMkdT__7jzO-qHQAgIxOy15ka4JGvqhi9fsB13RslsRNOpnk\",\n" +
            "    \"kty\": \"\",\n" +
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

        pathToResources = Paths.get(System.getProperty("user.dir"), "src", "test", "resources");
    }

    @Test
    void configurationPassNullClientIdThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new Configuration(null, "test",
            RSAKey.parse(validJwk)));
    }

    @Test
    void configurationPassNullClientAuthTypeThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new Configuration("test", null,
            RSAKey.parse(validJwk)));
    }

    @Test
    void configurationPassEmptyClientIdThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new Configuration("", "test",
            RSAKey.parse(validJwk)));
    }

    @Test
    void configurationPassEmptyClientAuthTypeThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new Configuration("test", "",
            RSAKey.parse(validJwk)));
    }

    @Test
    void configurationPassNullRsaKeyThrowsConfigurationException() {
        try {
            new Configuration("test", "test", null);
            fail();
        } catch (Exception e) {
            assertTrue(e instanceof ConfigurationException);
            assertEquals("JWK can not be null or have missing private key", e.getMessage());
        }
    }

    @Test
    void configurationPassValidConfigInstantiatesConfiguration() {
        try {
            new Configuration("test", "test", RSAKey.parse(validJwk));
            assertTrue(true);
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    @Test
    void configurationNullConfigPathThrowsConfigurationException() {
        assertThrows(ConfigurationException.class, () -> new Configuration(null));
    }

    @Test
    void configurationNonExistentConfigPathThrowsConfigurationException() {
        assertThrows(ConfigurationException.class, () -> new Configuration("somemoretests.txt"));
    }

    @Test
    void configurationInvalidJwkMissingDThrowsConfigurationException() {
        try {
            new Configuration(String.valueOf(Paths.get(String.valueOf(pathToResources), "invalidJwkKtyTypo.json")));
            fail();
        } catch (Exception e) {
            assertTrue(e instanceof ConfigurationException);
            assertEquals("Exception caught when retrieving contents from file", e.getMessage());
        }
    }

    @Test
    void configurationValidConfigPathEmptyFieldsThrowsConfigurationException() {
        try {
            new Configuration(String.valueOf(Paths.get(String.valueOf(pathToResources), "emptyValues.txt")));
            fail();
        } catch (Exception e) {
            assertTrue(e instanceof ConfigurationException);
            assertEquals("Exception caught when retrieving contents from file", e.getMessage());
        }
    }

    @Test
    void configurationValidConfigPathMissingFieldsThrowsConfigurationException() {
        assertThrows(ConfigurationException.class, () -> new Configuration(
            String.valueOf(Paths.get(String.valueOf(pathToResources),
                "emptyValues.txt")))
        );
    }

    @Test
    void configurationValidConfigPathValidConfigInstantiatesConfiguration() {
        try {
            Configuration configuration = new Configuration(String.valueOf(Paths.get(String.valueOf(pathToResources),
                "validConfigStructure.txt")));

            assertEquals("testClientId", configuration.getClientId());
            assertEquals("testClientAuthType", configuration.getClientAuthType());
            assertEquals(new URL(Constants.FACTSET_WELL_KNOWN_URI), configuration.getWellKnownUrl());

            assertEquals("RSA", configuration.getJwk().getKeyType().toString());
            assertEquals("sig", configuration.getJwk().getKeyUse().toString());
            assertEquals("RS256", configuration.getJwk().getAlgorithm().toString());
            assertEquals("testKid", configuration.getJwk().getKeyID());
            assertEquals("testD", configuration.getJwk().getPrivateExponent().toString());
            assertEquals("testN", configuration.getJwk().getModulus().toString());
            assertEquals("testP", configuration.getJwk().getFirstPrimeFactor().toString());
            assertEquals("testQ", configuration.getJwk().getSecondPrimeFactor().toString());
            assertEquals("testDp", configuration.getJwk().getFirstFactorCRTExponent().toString());
            assertEquals("testDq", configuration.getJwk().getSecondFactorCRTExponent().toString());
            assertEquals("testQi", configuration.getJwk().getFirstCRTCoefficient().toString());
            assertEquals("testE", configuration.getJwk().getPublicExponent().toString());
        } catch (Exception e) {
            fail();
        }
    }
}
