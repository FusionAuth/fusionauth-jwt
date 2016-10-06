## Prime JWT ![semver 2.0.0 compliant](http://img.shields.io/badge/semver-2.0.0-brightgreen.svg?style=flat-square)

### Example Code:

```java
Signer signer = new HmacSigner(Algorithm.HS256).withSecret("secret");
Verifier verifier = new Verifier().withSigner(signer);

// Build the signed JWT string
String jwt = new JWT().withSigner(signer)
    .subject("412d2f35-115e-4dd7-93f5-7bd3e06752ca")
    .get();

// Verify the JWT Signature
verifier.verify(jwt);
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
