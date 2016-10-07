## Prime JWT ![semver 2.0.0 compliant](http://img.shields.io/badge/semver-2.0.0-brightgreen.svg?style=flat-square)

This library is designed to be easy to use and thread-safe. Once you construct a new Signer or Verifier they may be re-used to encode and decode JWTs.

## Example Code:

### Encode a JWT using Hmac
```java
Signer signer = HmacSigner.newSha256Signer("secret");

JWT jwt = new JWT().with(t -> t.subject = "f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3");
String encodedJwt = JWT.getEncoder().encode(jwt, signer);

```

### Decode a JWT using Hmac
```java
Verifier verifier = new HmacVerifier("secret");

JWT jwt = JWT.getDecoder().decode(encodedJwt, verifier);
assertEquals(jwt.subject, "f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3");
```

To use a higher strength hash, all you need to change in the above examples is the signer. The rest is taken care of for you.
```java
Signer signer = HmacSigner.newSha512Signer("secret");
```

### Encode a JWT using RSA
```java
Signer signer = RSASigner.newRSA256Signer(new String(Files.readAllBytes(Paths.get("private_key.pem"))));


JWT jwt = new JWT().with(t -> t.subject = "f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3");
String encodedJwt = JWT.getEncoder().encode(jwt, signer);

```

### Decode a JWT using RSA
```java
Verifier verifier = new RSAVerifier(new String(Files.readAllBytes(Paths.get("public_key.pem"))));

JWT jwt = JWT.getDecoder().decode(encodedJwt, verifier);
assertEquals(jwt.subject, "f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3");
```

To use a higher strength hash, all you need to change in the above examples is the signer. The rest is taken care of for you.
```java
Signer signer = RSASigner.newRSA512Signer(new String(Files.readAllBytes(Paths.get("private_key.pem"))));
```

### Supported JSON Web Algorithms (JWA) as described in RFC 7518

HS256, HS512, RS256, RS512, none (Unsecured)

## Building

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
