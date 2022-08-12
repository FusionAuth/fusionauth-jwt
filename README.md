## FusionAuth JWT ![semver 2.0.0 compliant](http://img.shields.io/badge/semver-2.0.0-brightgreen.svg?style=flat-square) ![Tests](https://github.com/FusionAuth/fusionauth-jwt/workflows/Tests/badge.svg)
FusionAuth JWT is intended to be fast and easy to use. FusionAuth JWT has a single external dependency on Jackson, no Bouncy Castle, Apache Commons or Guava.

## Security disclosures
If you find a vulnerability or other security related bug, please send a note to security@fusionauth.io before opening a GitHub issue. This will allow us to assess the disclosure and prepare a fix prior to a public disclosure. 

We are very interested in compensating anyone that can identify a security related bug or vulnerability and properly disclose it to us.

## Features
 - JWT signing using HMAC, RSA and Elliptic Curve support
   - `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`
 - JWT signing using RSA-PSS signatures
   - `PS256`, `PS384`, `PS512`
   - Requires Java 8 update 251 or greater, or any version that includes support RSASSA-PSS
   - https://bugs.java.com/bugdatabase/view_bug.do?bug_id=JDK-8146293
   - Available in versions >= 3.5.0
 - Modular crypto provider so you can drop in support for BC FIPS or other JCE security providers.   
 - PEM decoding / encoding
   - Decode PEM files to PrivateKey or PublicKey
     - Decode private EC keys un-encapsulated in PKCS#8, returned PEM will be in PKCS#8 form.
     - Both public and private keys will be returned when encoded in the private PEM
   - Encode PrivateKey or PublicKey to PEM
 - JSON Web Key 
   - Build JWK from Private Key
   - Build JWK from Public Key
   - Build JWK from PEM
   - Parse public keys from a JSON Web Key
   - Retrieve JWK from JWKS endpoints
 - Helpers
   - Generate RSA Key Pairs in `2048`, `3072` or `4096` bit sizes
   - Generate EC Key Pairs in `256`, `384` and `521` bit sizes
   - Generate `x5t` and `x5t#256` values from X.509 Certificates
   - Generate JWK thumbprint using `SHA-1` or `SHA-256` 
   - Generate ideal HMAC secret lengths for `SHA-256`, `SHA-384` and `SHA-512`
   - Generate the `at_hash` and `c_hash` claims for OpenID Connect

## Get it

### Maven
 ```xml
<dependency>
  <groupId>io.fusionauth</groupId>
  <artifactId>fusionauth-jwt</artifactId>
  <version>5.2.0</version>
</dependency>
 ```

### Gradle
```groovy
implementation 'io.fusionauth:fusionauth-jwt:5.2.1'
```

### Gradle Kotlin
```kotlin
implementation("io.fusionauth:fusionauth-jwt:5.2.1")
```

### Savant 
```groovy
dependency(id: "io.fusionauth:fusionauth-jwt:5.2.1")
```

For others see [https://search.maven.org](https://search.maven.org/artifact/io.fusionauth/fusionauth-jwt/4.0.1/jar).
 
## Example Code:

### JWT Signing and Verifying

#### Sign and encode a JWT using HMAC
```java
// Build an HMAC signer using a SHA-256 hash
Signer signer = HMACSigner.newSHA256Signer("too many secrets");

// Build a new JWT with an issuer(iss), issued at(iat), subject(sub) and expiration(exp)
JWT jwt = new JWT().setIssuer("www.acme.com")
                   .setIssuedAt(ZonedDateTime.now(ZoneOffset.UTC))
                   .setSubject("f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3")
                   .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60));
                       
// Sign and encode the JWT to a JSON string representation
String encodedJWT = JWT.getEncoder().encode(jwt, signer);
```

A higher strength hash can be used by changing the signer. The encoding and decoding steps are not affected.
```java
// Build an HMAC signer using a SHA-384 hash
Signer signer384 = HMACSigner.newSHA384Signer("too many secrets");

// Build an HMAC signer using a SHA-512 hash
Signer signer512 = HMACSigner.newSHA512Signer("too many secrets");
```

#### Verify and decode a JWT using HMAC
```java
// Build an HMC verifier using the same secret that was used to sign the JWT
Verifier verifier = HMACVerifier.newVerifier("too many secrets");

// Verify and decode the encoded string JWT to a rich object
JWT jwt = JWT.getDecoder().decode(encodedJWT, verifier);

// Assert the subject of the JWT is as expected
assertEquals(jwt.subject, "f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3");
```

#### Sign and encode a JWT using RSA
```java
// Build an RSA signer using a SHA-256 hash. A signer may also be built using the PrivateKey object.
Signer signer = RSASigner.newSHA256Signer(new String(Files.readAllBytes(Paths.get("private_key.pem"))));

// Build a new JWT with an issuer(iss), issued at(iat), subject(sub) and expiration(exp)
JWT jwt = new JWT().setIssuer("www.acme.com")
                   .setIssuedAt(ZonedDateTime.now(ZoneOffset.UTC))
                   .setSubject("f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3")
                   .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60));
        
// Sign and encode the JWT to a JSON string representation
String encodedJWT = JWT.getEncoder().encode(jwt, signer);
```

A higher strength hash can be used by changing the signer. The encoding and decoding steps are not affected.
```java
// Build an RSA signer using a SHA-384 hash
Signer signer = RSASigner.newSHA384Signer(new String(Files.readAllBytes(Paths.get("private_key.pem"))));

// Build an RSA signer using a SHA5124 hash
Signer signer = RSASigner.newSHA512Signer(new String(Files.readAllBytes(Paths.get("private_key.pem"))));
```

#### Verify and decode a JWT using RSA
```java
// Build an RSA verifier using an RSA Public Key. A verifier may also be built using the PublicKey object.
Verifier verifier = RSAVerifier.newVerifier(Paths.get("public_key.pem"));

// Verify and decode the encoded string JWT to a rich object
JWT jwt = JWT.getDecoder().decode(encodedJWT, verifier);

// Assert the subject of the JWT is as expected
assertEquals(jwt.subject, "f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3");
```

#### Sign and encode a JWT using EC
```java
// Build an EC signer using a SHA-256 hash. A signer may also be built using the PrivateKey object.
Signer signer = ECSigner.newSHA256Signer(new String(Files.readAllBytes(Paths.get("private_key.pem"))));

// Build a new JWT with an issuer(iss), issued at(iat), subject(sub) and expiration(exp)
JWT jwt = new JWT().setIssuer("www.acme.com")
                   .setIssuedAt(ZonedDateTime.now(ZoneOffset.UTC))
                   .setSubject("f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3")
                   .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60));
        
// Sign and encode the JWT to a JSON string representation
String encodedJWT = JWT.getEncoder().encode(jwt, signer);
```

A higher strength hash can be used by changing the signer. The encoding and decoding steps are not affected.
```java
// Build an EC signer using a SHA-384 hash
Signer signer = ECSigner.newSHA384Signer(new String(Files.readAllBytes(Paths.get("private_key.pem"))));

// Build an EC signer using a SHA-512 hash
Signer signer = ECSigner.newSHA512Signer(new String(Files.readAllBytes(Paths.get("private_key.pem"))));
```

#### Verify and decode a JWT using EC
```java
// Build an EC verifier using an EC Public Key. A verifier may also be built using the PublicKey object.
Verifier verifier = ECVerifier.newVerifier(Paths.get("public_key.pem"));

// Verify and decode the encoded string JWT to a rich object
JWT jwt = JWT.getDecoder().decode(encodedJWT, verifier);

// Assert the subject of the JWT is as expected
assertEquals(jwt.subject, "f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3");
```

#### Verify a JWT adjusting for Clock Skew
```java
// Build an EC verifier using an EC Public Key
Verifier verifier = ECVerifier.newVerifier(Paths.get("public_key.pem"));

// Verify and decode the encoded string JWT to a rich object and allow up to 60 seconds
// of clock skew when asserting the 'exp' and 'nbf' claims if they exist.
JWT jwt = JWT.getDecoder().withClockSkew(60).decode(encodedJWT, verifier);

// Assert the subject of the JWT is as expected
assertEquals(jwt.subject, "f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3");
```

#### Verify an expired JWT by going back in time
In a scenario where you may have a hard coded JWT in a test case that you wish to validate, you may use the time machine JWT decoder. Ideally you would not hard code JWTs in your tests and instead generate a new one each time so that the JWT would pass the expiration check. If this is not possible, this option is provided.
```java
// Build an EC verifier using an EC Public Key
Verifier verifier = ECVerifier.newVerifier(Paths.get("public_key.pem"));

// Using the time machine decoder, you may adjust 'now' to any point in the past, or future.
// Note, this is only provided for testing, and should not be used in production.
ZonedDateTime thePast = ZonedDateTime.of(2019, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC) 
JWT jwt = JWT.getTimeMachineDecoder(thePast).decode(encodedJWT, verifier);

// Assert the subject of the JWT is as expected
assertEquals(jwt.subject, "f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3");
```


### Build a Signer, or a Verifier using a provided CryptoProvider

This pattern is available on the HMAC, RSA and EC verifier and signers.
 
```java
// Build and EC signer using a BC Fips ready Crypto Provider
Signer signer = ECSigner.newSHA256Signer(new String(Files.readAllBytes(Paths.get("private_key.pem"))), new BCFIPSCryptoProvider());

// Build an EC verifier using a BC Fips ready Crypto Provider
Verifier verifier = ECVerifier.newVerifier(Paths.get("public_key.pem"), new BCFIPSCryptoProvider());
```

## JSON Web Keys

### Retrieve JSON Web Keys from a JWKS endpoint

```java
// Retrieve JSON Web Keys using a known JWKS endpoint
// - You may optionally provide a HttpURLConnection to this method instead of a string if you want to build your own connection.
List<JSONWebKey> keys = JSONWebKeySetHelper.retrieveKeysFromJWKS("https://www.googleapis.com/oauth2/v3/certs");

// Retrieve JSON Web Keys using a well known OpenID Connect configuration endpoint
// - You may optionally provide a HttpURLConnection to this method instead of a string if you want to build your own connection.
List<JSONWebKey> keys = JSONWebKeySetHelper.retrieveKeysFromWellKnownConfiguration("https://accounts.google.com/.well-known/openid-configuration");

// Retrieve JSON Web Keys using an OpenID Connect issuer endpoint
List<JSONWebKey> keys = JSONWebKeySetHelper.retrieveKeysFromIssuer("https://accounts.google.com");
```

### Convert a Public Key to JWK

```java
JSONWebKey jwk = JSONWebKey.build(publicKey);
String json = jwk.toJSON();
```

```json
{
  "e": "AQAB",
  "kty": "RSA",
  "n": "Auchby3lZKHbiAZrTkJh79hJvgC3W7STSS4y6UZEhhxx3m3W2hD8qCyw6BEyrciPpwou-vmeDN7qBSk2QKqTTjlg5Pkf8O4z8d9HAlBTUDg4p98qLFOF2EFWWTiFbQwAP2qODOIv9WCAM2rkXEPwGiF962XAoOwiSmldeDu7Uo5A-bnTi0z3oNu4qm_48kv90o9CMiELszE9jsfoH32WE71HDqhsRjVNddDJ81e5zxBN8UEmaR-gmWqa63laON2KANPugJP7PrYJ_PC9ilQfV3F1rDpqbvlFQkshohJ39VrVpEtSRmJ12nqTFuspXLApekOyic3J9jo6ZI7o3IdQmy3bpnJIT_U",
  "use": "sig"
}
```

### Extract the Public Key from a JWK

```json
{
  "e": "AQAB",
  "kty": "RSA",
  "n": "Auchby3lZKHbiAZrTkJh79hJvgC3W7STSS4y6UZEhhxx3m3W2hD8qCyw6BEyrciPpwou-vmeDN7qBSk2QKqTTjlg5Pkf8O4z8d9HAlBTUDg4p98qLFOF2EFWWTiFbQwAP2qODOIv9WCAM2rkXEPwGiF962XAoOwiSmldeDu7Uo5A-bnTi0z3oNu4qm_48kv90o9CMiELszE9jsfoH32WE71HDqhsRjVNddDJ81e5zxBN8UEmaR-gmWqa63laON2KANPugJP7PrYJ_PC9ilQfV3F1rDpqbvlFQkshohJ39VrVpEtSRmJ12nqTFuspXLApekOyic3J9jo6ZI7o3IdQmy3bpnJIT_U",
  "use": "sig"
}
```

```java
String json = { ... example above ... }
byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
JSONWebKey jwk = Mapper.deserialize(bytes, JSONWebKey.class);
PublicKey publicKey = JSONWebKey.parse(jwk);
```

### Convert a Private Key to JWK

```java
JSONWebKey jwk = JSONWebKey.build(privateKey);
String json = jwk.toJSON();
```

```json
{
  "p": "9dy6wUxA0eOHopUP-E5QjDzuW8rXdaQMR566oDJ1qL0iD0koQAB9X3hboB-2Rru0aATu6WDW-jd4mgtYnXO8ow",
  "kty": "RSA",
  "q": "6Nfc6c8meTRkVRAHCF24LB5GLfsjoMB0tOeEO9w9Ous1a4o-D24bAePMUImAp3woFoNDRfWtlNktOqLel5Pjew",
  "d": "C0G3QGI6OQ6tvbCNYGCqq043YI_8MiBl7C5dqbGZmx1ewdJBhMNJPStuckhskURaDwk4-8VBW9SlvcfSJJrnZhgFMjOYSSsBtPGBIMIdM5eSKbenCCjO8Tg0BUh_xa3CHST1W4RQ5rFXadZ9AeNtaGcWj2acmXNO3DVETXAX3x0",
  "e": "AQAB",
  "use": "sig",
  "qi": "XLE5O360x-MhsdFXx8Vwz4304-MJg-oGSJXCK_ZWYOB_FGXFRTfebxCsSYi0YwJo-oNu96bvZCuMplzRI1liZw",
  "dp": "32QGgDmjr9GX3N6p2wh1YWa_gMHmUSqUScLseUA_7eijeNYU70pCoCtAvVXzDYPhoJ3S4lQuIL2kI_tpMe8GFw",
  "dq": "21tJjqeN-k-mWhCwX2xTbpTSzsyy4uWMzUTy6aXxtUkTWY2yK70yClS-Df2MS70G0za0MPtjnUAAgSYhB7HWcw",
  "n": "359ZykLITko_McOOKAtpJRVkjS5itwZxzjQidW2X6tBEOYCH4LZbwfj8fGGvlUtzpyuwnYuIlNX8TvZLTenOk45pphXr5PMCMKi7YZgkhd6_t_oeHnXY-4bnDLF1r9OUFKwj6C-mFFM-woKc-62tuK6QJiuc-5bFfn9wRL15K1E"
}
```

### Add a custom property to a JWK

```java
JSONWebKey jwk = JSONWebKey.build(privateKey)
                           .add("boom", "goes the dynamite")
                           .add("more", "cowbell");
String json = jwk.toJSON();
```

```json
{
  "alg" : "ES256",
  "boom" : "goes the dynamite",
  "crv" : "P-256",
  "kty" : "EC",
  "more" : "cowbell",
  "use" : "sig",
  "x" : "NIWpsIea0qzB22S0utDG8dGFYqEInv9C7ZgZuKtwjno",
  "y" : "iVFFtTgiInz_fjh-n1YqbibnUb2vtBZFs3wPpQw3mc0"
}
```

## Building
 
## Building with Maven
 ```bash
 $ mvn install
 ```


## Building with Savant

```bash
$ sb int
```

**Note:** If you do not yet have Savant build tool installed, use the following instructions.

```bash
$ mkdir ~/savant
$ cd ~/savant
$ wget http://savant.inversoft.org/org/savantbuild/savant-core/1.0.0/savant-1.0.0.tar.gz
$ tar xvfz savant-1.0.0.tar.gz
$ ln -s ./savant-1.0.0 current
$ export PATH=$PATH:~/savant/current/bin/
```

For more information, checkout [savantbuild.org](http://savantbuild.org/).
