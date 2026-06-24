# FusionAuth JWT

[![Build Status](#)](#)
[![Maven Central](#)](#)
[![License](#)](#)

A **fast, lightweight, and dependency-minimal** Java library for working with JSON Web Tokens (JWT).

FusionAuth JWT is designed with simplicity and performance in mind:

* ✅ **Only one dependency**: Jackson
* 🚫 No Bouncy Castle, Apache Commons, or Guava required
* ⚡ Optimized for speed and minimal footprint

---

## 📚 Table of Contents

* [Security Disclosures](#-security-disclosures)
* [Features](#-features)
* [Supported Algorithms](#-supported-algorithms)
* [Installation](#-installation)
* [Usage](#-usage)

  * [HMAC Operations](#hmac-operations)
  * [RSA Operations](#rsa-operations)
  * [EC Operations](#ec-operations)
  * [Clock Skew & Time Machine](#clock-skew--time-machine)
  * [JCE Providers](#jce-providers)
  * [JSON Web Keys (JWK)](#json-web-keys-jwk)
* [Building](#-building)
* [Contributing](#-contributing)

---

## 🔐 Security Disclosures

> ⚠️ **Important for Security Researchers**
>
> If you discover a vulnerability or security-related issue:
>
> * **DO NOT open a public GitHub issue**
> * Instead, report it privately to the maintainers
>
> This allows time to assess and fix the issue before disclosure.
>
> 💡 Responsible disclosures may be eligible for compensation.

---

## ✨ Features

### JWT Support

* Sign and verify JWTs
* Minimal dependencies (Jackson only)
* High-performance encoding/decoding

### PEM Utilities

* Decode PEM → `PrivateKey` / `PublicKey`
* Encode keys → PEM
* Supports PKCS#8 conversion

### JSON Web Keys (JWK)

* Build JWK from keys or PEM
* Parse public keys from JWK
* Retrieve keys from JWKS endpoints

### Helper Utilities

* RSA, EC, EdDSA key generation
* JWK thumbprints (SHA-1 / SHA-256)
* OpenID Connect helpers (`at_hash`, `c_hash`)
* HMAC secret generation

---

## 🔑 Supported Algorithms

| Category       | Algorithms          |
| -------------- | ------------------- |
| HMAC           | HS256, HS384, HS512 |
| RSA            | RS256, RS384, RS512 |
| RSA-PSS        | PS256, PS384, PS512 |
| Elliptic Curve | ES256, ES384, ES512 |
| Edwards Curve  | Ed25519, Ed448      |

📌 Full reference: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms

> ⚠️ Note:
>
> * `EdDSA` is deprecated → use `Ed25519` or `Ed448`
> * `Ed448` requires SHAKE256 support (e.g., Bouncy Castle)

---

## 📦 Installation

### Maven

```xml
<dependency>
  <groupId>io.fusionauth</groupId>
  <artifactId>fusionauth-jwt</artifactId>
  <version>6.0.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'io.fusionauth:fusionauth-jwt:6.0.0'
```

### Gradle (Kotlin)

```kotlin
implementation("io.fusionauth:fusionauth-jwt:6.0.0")
```

### Savant

```groovy
dependency(id: "io.fusionauth:fusionauth-jwt:6.0.0")
```

More options: https://search.maven.org

---

## 🚀 Usage

### HMAC Operations

#### Sign a JWT

```java
Signer signer = HMACSigner.newSHA256Signer("too many secrets");

JWT jwt = new JWT()
    .setIssuer("www.acme.com")
    .setIssuedAt(ZonedDateTime.now(ZoneOffset.UTC))
    .setSubject("f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3")
    .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60));

String encodedJWT = JWT.getEncoder().encode(jwt, signer);
```

#### Verify a JWT

```java
Verifier verifier = HMACVerifier.newVerifier("too many secrets");

JWT jwt = JWT.getDecoder().decode(encodedJWT, verifier);

assertEquals("f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3", jwt.subject);
```

---

### RSA Operations

#### Sign

```java
Signer signer = RSASigner.newSHA256Signer(
    new String(Files.readAllBytes(Paths.get("private_key.pem")))
);

String encodedJWT = JWT.getEncoder().encode(jwt, signer);
```

#### Verify

```java
Verifier verifier = RSAVerifier.newVerifier(Paths.get("public_key.pem"));

JWT jwt = JWT.getDecoder().decode(encodedJWT, verifier);
```

---

### EC Operations

#### Sign

```java
Signer signer = ECSigner.newSHA256Signer(
    new String(Files.readAllBytes(Paths.get("private_key.pem")))
);

String encodedJWT = JWT.getEncoder().encode(jwt, signer);
```

#### Verify

```java
Verifier verifier = ECVerifier.newVerifier(Paths.get("public_key.pem"));

JWT jwt = JWT.getDecoder().decode(encodedJWT, verifier);
```

---

### Clock Skew & Time Machine

#### Allow Clock Skew

```java
JWT jwt = JWT.getDecoder()
    .withClockSkew(60)
    .decode(encodedJWT, verifier);
```

#### Time Machine (Testing Only)

```java
ZonedDateTime past = ZonedDateTime.of(
    2019, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC
);

JWT jwt = JWT.getTimeMachineDecoder(past)
    .decode(encodedJWT, verifier);
```

---

### JCE Providers

```java
Security.insertProviderAt(new BouncyCastleFipsProvider(), 1);
```

---

### JSON Web Keys (JWK)

#### Retrieve Keys

```java
List<JSONWebKey> keys =
    JSONWebKeySetHelper.retrieveKeysFromJWKS(
        "https://www.googleapis.com/oauth2/v3/certs"
    );
```

#### Convert Public Key → JWK

```java
JSONWebKey jwk = JSONWebKey.build(publicKey);
String json = jwk.toJSON();
```

#### Parse JWK → Public Key

```java
byte[] bytes = json.getBytes(StandardCharsets.UTF_8);

JSONWebKey jwk = Mapper.deserialize(bytes, JSONWebKey.class);
PublicKey publicKey = JSONWebKey.parse(jwk);
```

#### Add Custom Fields

```java
JSONWebKey jwk = JSONWebKey.build(privateKey)
    .add("custom", "value");

String json = jwk.toJSON();
```

---

## 🛠️ Building

### Maven

```bash
mvn install
```

### Savant

```bash
sb int
```

### Install Savant

```bash
mkdir ~/savant
cd ~/savant
wget http://savant.inversoft.org/org/savantbuild/savant-core/2.0.2/savant-2.0.2.tar.gz
tar xvfz savant-2.0.2.tar.gz
ln -s ./savant-2.0.2 current
export PATH=$PATH:~/savant/current/bin/
```

---

## 🤝 Contributing

Contributions are welcome!
Please follow standard GitHub workflows:

1. Fork the repository
2. Create a feature branch
3. Submit a Pull Request

---

## 📄 License

See the LICENSE file for details.

---
