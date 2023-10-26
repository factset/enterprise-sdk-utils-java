<img alt="FactSet" src="https://www.factset.com/hubfs/Assets/images/factset-logo.svg" height="56" width="290">

# FactSet SDK Utilities for Java

[![Maven Central](https://img.shields.io/maven-central/v/com.factset.sdk/utils)](https://search.maven.org/artifact/com.factset.sdk/utils)

[![Apache-2 license](https://img.shields.io/badge/license-Apache2-brightgreen.svg)](https://www.apache.org/licenses/LICENSE-2.0)

This repository contains a collection of utilities that supports FactSet's SDK in Java and facilitate usage of FactSet APIs.

## Installation

### Maven

Add the below dependency to the project's POM:

```xml
<dependency>
    <groupId>com.factset.sdk</groupId>
    <artifactId>utils</artifactId>
    <version>1.1.0</version>
</dependency>
```

### Gradle

Add these dependencies to your project's build file:

```groovy
repositories {
    mavenCentral()
}

dependencies {
    implementation "com.factset.sdk:utils:1.1.0"
}
```

### Snapshot Releases

To be able to install snapshot releases of the sdk an additional repository must be added to the maven or gradle config.

#### Maven Snapshot Repository

```xml
<repositories>
    <repository>
        <id>sonatype</id>
        <name>sonatype-snapshot</name>
        <url>https://oss.sonatype.org/content/repositories/snapshots/</url>
        <snapshots>
            <enabled>true</enabled>
        </snapshots>
        <releases>
            <enabled>false</enabled>
        </releases>
    </repository>
</repositories>
```

#### Gradle Snapshot Repository

```groovy
repositories {
    mavenCentral()
    maven {
        url = uri("https://oss.sonatype.org/content/repositories/snapshots/")
        mavenContent {
            snapshotsOnly()
        }
    }
}
```

Snapshot releases are cached by gradle for some time, for details see: [Gradle Dynamic Versions](https://docs.gradle.org/current/userguide/dynamic_versions.html#sub:declaring_dependency_with_changing_version)


## Usage

This library contains multiple modules, sample usage of each module is below.

### Authentication

First, you need to create the OAuth 2.0 client configuration that will be used to authenticate against FactSet's APIs:

1. [Create a new application](https://developer.factset.com/learn/authentication-oauth2#creating-an-application) on FactSet's Developer Portal.
2. When prompted, download the configuration file and move it to your development environment.

```java
package com.factset.sdk.console;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.HttpURLConnection;

import com.factset.sdk.utils.authentication.ConfidentialClient;

public class Console {

    public static void main(String[] args) {
        HttpURLConnection connection = null;
        try {
            // The ConfidentialClient instance should be reused in production environments.
            ConfidentialClient confidentialClient = new ConfidentialClient("./path/to/config.json");

            String token = confidentialClient.getAccessToken();
            String bearerHeader = "Bearer " + token;

            URL url = new URL("https://api.factset.com/analytics/lookups/v3/currencies");

            connection = (HttpURLConnection) url.openConnection();

            connection.setRequestMethod("GET");
            connection.setRequestProperty("Authorization", bearerHeader);
            connection.setRequestProperty("Content-Type", "application/json");

            InputStream is = connection.getInputStream();
            BufferedReader rd = new BufferedReader(new InputStreamReader(is));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = rd.readLine()) != null) {
                response.append(line);
                response.append('\r');
            }
            rd.close();

            System.out.println(token);
            System.out.println(response);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
}
```

### Configure a Proxy

The Confidential Client accepts an additional optional parameter called `RequestOptions`. This can be created to specify a proxy for the client to use. Below is an example of how to do this:

```java
Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 8080));
RequestOptions requestOptions = RequestOptions.builder().proxy(proxy).build();

// Pass this into client
ConfidentialClient confidentialClient = new ConfidentialClient("./path/to/config.json", requestOptions);
```

### Custom SSL Certificate

If you are making requests to a server which is using custom TLS certificates, you are able to verify the validity of the certificate via the `RequestOptions` configuration.

#### Hostname Verifier

You can pass in a custom hostname verifier to modify the details of the verification with a custom implementation. Otherwise, the `RequestOptions` will use the default one which checks the hostname in the certificate, located in the JRE keystore, and compares it to the hostname of the URL that is being hit by the client.

#### SSL Socket Factory

You can pass in a custom SSL Socket Factory and modify the `SSLContext` for a specific user use case. Otherwise, the `RequestOptions` uses a default `SSLSocketFactory` as described [here](https://docs.oracle.com/javase/7/docs/api/javax/net/ssl/HttpsURLConnection.html#getDefaultHostnameVerifier()).

#### Example

```java
SSLContext sslContext = SSLContext.getInstance("TLS");
sslContext.init(...); // Configure this based on application's needs

SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
HostnameVerifier hostnameVerifier = ((hostname, session) -> ...); // Configure this based on application's needs

RequestOptions reqOpt = RequestOptions.builder()
        .hostnameVerifier(hostnameVerifier)
        .sslSocketFactory(sslSocketFactory)
        .build();
```

## Modules

Information about the various utility modules contained in this library can be found below.

### Authentication

The [authentication module](src/main/java/com/factset/sdk/utils/authentication) provides helper classes that facilitate [OAuth 2.0](https://developer.factset.com/learn/authentication-oauth2) authentication and authorization with FactSet's APIs. Currently the module has support for the [client credentials flow](https://github.com/factset/oauth2-guidelines#client-credentials-flow-1).

Each helper class in the module has the following features:

* Accepts a `Configuration` instance that contains information about the OAuth 2.0 client, including the client ID and private key.
* Performs authentication with FactSet's OAuth 2.0 authorization server and retrieves an access token.
* Caches the access token for reuse and requests a new access token as needed when one expires.
    * In order for this to work correctly, the helper class instance should be reused in production environments.

#### Configuration

Classes in the authentication module require OAuth 2.0 client configuration information to be passed to the constructor in the `ConfidentialClient` through a JSON-formatted file or a `Configuration` object. Below is an example of a JSON-formatted file:

```json
{
    "name": "Application name registered with FactSet's Developer Portal",
    "clientId": "OAuth 2.0 Client ID registered with FactSet's Developer Portal",
    "clientAuthType": "Confidential",
    "owners": ["USERNAME-SERIAL"],
    "jwk": {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "Key ID",
        "d": "ECC Private Key",
        "n": "Modulus",
        "e": "Exponent",
        "p": "First Prime Factor",
        "q": "Second Prime Factor",
        "dp": "First Factor CRT Exponent",
        "dq": "Second Factor CRT Exponent",
        "qi": "First CRT Coefficient"
    }
}
```

The other option is to pass in the `Configuration` instance which is initialised as shown below:

```java
import com.factset.sdk.utils.authentication.Configuration;
import com.nimbusds.jose.jwk.RSAKey;
import org.json.JSONObject;

JSONObject jsonObject = new JSONObject(
  "{ 'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': 'Key ID', 'd': 'ECC Private Key', 'n': 'Modulus', 'e': 'AQAB','p': 'First Prime Factor', 'q': 'Second Prime Factor', 'dp': 'First Factor CRT Exponent', 'dq': 'Second Factor CRT Exponent', 'qi': 'First CRT Coefficient' }"
);

RSAKey jwk = RSAKey.parse(jsonObject.toString());
Configuration conf = new Configuration("client id", "Confidential", jwk);
```

If you're just starting out, you can visit FactSet's Developer Portal to [create a new application](https://developer.factset.com/applications) and download a configuration file in this format.

If you're creating and managing your signing key pair yourself, see the required [JWK parameters](https://github.com/factset/oauth2-guidelines#jwk-parameters) for public-private key pairs.

# Contributing

Please refer to the [contributing guide](CONTRIBUTING.md).

# Logging

All logger names start with "com.factset".

This library uses [SLF4J](https://www.slf4j.org/) as logging interface,
which requires a [binding](https://www.slf4j.org/manual.html#swapping) to your logging framework on the classpath.

If no binding is found, SLF4J prints out the following warning and then defaults to a no-operation
implementation, which discard all logs:
```
SLF4J: Failed to load class "org.slf4j.impl.StaticLoggerBinder".
SLF4J: Defaulting to no-operation (NOP) logger implementation
SLF4J: See http://www.slf4j.org/codes.html#StaticLoggerBinder for further details.
```

# Troubleshooting

### "Unsuccessful token response: Failed to authenticate or parse the token"

This error occurs when the request for an OAuth 2.0 Access Token got a non-200 response
that could not be parsed as an [OAuth 2.0 Error Response](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2).

Additional logging can be enabled to troubleshoot the problem:
The logger `com.factset.sdk.utils.authentication.ConfidentialClient` logs out the exact response in log level `TRACE`.

# Copyright

Copyright 2023 FactSet Research Systems Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
