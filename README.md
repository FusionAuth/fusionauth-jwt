## Prime JWT ![semver 2.0.0 compliant](http://img.shields.io/badge/semver-2.0.0-brightgreen.svg?style=flat-square)

## Example Code:

### Encode a JWT using HMAC
```java
Signer signer = HMACSigner.newSHA256Signer("too many secrets");

JWT jwt = new JWT().setIssuer("www.acme.com")
                   .setIssuedAt(ZonedDateTime.now(ZoneOffset.UTC))
                   .setSubject("f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3")
                   .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60));
                       
String encodedJWT = JWT.getEncoder().encode(jwt, signer);

```

A higher strength hash can be used by changing the signer. The encoding and decoding steps are not affected.
```java
Signer signer = HMACSigner.newSHA512Signer("too many secrets");
```

### Decode a JWT using HMAC
```java
Verifier verifier = HMACVerifier.newVerifier("too many secrets");

JWT jwt = JWT.getDecoder().decode(encodedJWT, verifier);
assertEquals(jwt.subject, "f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3");
```

### Encode a JWT using RSA
```java
Signer signer = RSASigner.newSHA256Signer(new String(Files.readAllBytes(Paths.get("private_key.pem"))));

JWT jwt = new JWT().setIssuer("www.acme.com")
                   .setIssuedAt(ZonedDateTime.now(ZoneOffset.UTC))
                   .setSubject("f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3")
                   .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60));
        
String encodedJWT = JWT.getEncoder().encode(jwt, signer);
```

A higher strength hash can be used by changing the signer. The encoding and decoding steps are not affected.
```java
Signer signer = RSASigner.newSHA512Signer(new String(Files.readAllBytes(Paths.get("private_key.pem"))));
```

### Decode a JWT using RSA
```java
Verifier verifier = RSAVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("public_key.pem"))));

JWT jwt = JWT.getDecoder().decode(encodedJWT, verifier);
assertEquals(jwt.subject, "f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3");
```

### Supported JSON Web Algorithms (JWA) as described in RFC 7518

HS256, HS384, HS512, RS256, RS384, RS512, none (Unsecured)

 # Maven 
 ```xml
<dependency>
  <groupId>com.inversoft</groupId>
  <artifactId>prime-jwt</artifactId>
  <version>1.2.1</version>
</dependency>
 ```

## Building with Savant

**Note:** This project uses the Savant build tool. To compile using using Savant, follow these instructions:

```bash
$ mkdir ~/savant
$ cd ~/savant
$ wget http://savant.inversoft.org/org/savantbuild/savant-core/1.0.0/savant-1.0.0.tar.gz
$ tar xvfz savant-1.0.0.tar.gz
$ ln -s ./savant-1.0.0 current
$ export PATH=$PATH:~/savant/current/bin/
```

Then, perform an integration build of the project by running:
```bash
$ sb int
```

For more information, checkout [savantbuild.org](http://savantbuild.org/).
