## Prime JWT ![semver 2.0.0 compliant](http://img.shields.io/badge/semver-2.0.0-brightgreen.svg?style=flat-square)

### Example Code:

```java
// JWT Producer, build a JWT, sign and encode
Signer signer = HmacSigner.newSha256Signer("secret");
JWT jwt = new JWT().with(t -> t.subject = "412d2f35-115e-4dd7-93f5-7bd3e06752ca");

String encodedJwt = JWT.getEncoder().encode(jwt, signer);
```

```java
// JWT Consumer. Verify and decode the JWT claims
Verifier verifier = new HmacVerifier("secret");
String encodedJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.eP0iQgy3kRGQrNCLumJBf_nKatW8Ydg0yAz37Vea-jk";

JWT jwt = JWT.getDecoder().decode(encodedJwt, verifier);
assertEquals(jwt.subject, "412d2f35-115e-4dd7-93f5-7bd3e06752ca");
```

### Supported JSON Web Algorithms (JWA) as described in RFC 7518

  - HS256
  - HS512
  - RS256
  - RS512
  - none (Unsecured)

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
