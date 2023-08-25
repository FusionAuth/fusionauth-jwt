package io.fusionauth.jwt.hmac;

import io.fusionauth.jwt.BaseJWTTest;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.ec.EC;
import io.fusionauth.jwt.rsa.RSA;
import org.testng.annotations.Test;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class HMACVerifierTest extends BaseJWTTest {
  @Test
  public void canVerify() {
    Verifier verifier = HMACVerifier.newVerifier("secret");

    assertFalse(verifier.canVerify(EC.ES256));
    assertFalse(verifier.canVerify(EC.ES384));
    assertFalse(verifier.canVerify(EC.ES512));

    assertTrue(verifier.canVerify(HMAC.HS256));
    assertTrue(verifier.canVerify(HMAC.HS384));
    assertTrue(verifier.canVerify(HMAC.HS512));

    assertFalse(verifier.canVerify(RSA.PS256));
    assertFalse(verifier.canVerify(RSA.PS384));
    assertFalse(verifier.canVerify(RSA.PS512));

    assertFalse(verifier.canVerify(RSA.RS256));
    assertFalse(verifier.canVerify(RSA.RS384));
    assertFalse(verifier.canVerify(RSA.RS512));
  }
}
