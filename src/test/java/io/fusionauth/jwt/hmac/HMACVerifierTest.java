package io.fusionauth.jwt.hmac;

import io.fusionauth.jwt.BaseJWTTest;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.Algorithm;
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

    assertFalse(verifier.canVerify(Algorithm.ES256));
    assertFalse(verifier.canVerify(Algorithm.ES384));
    assertFalse(verifier.canVerify(Algorithm.ES512));

    assertTrue(verifier.canVerify(Algorithm.HS256));
    assertTrue(verifier.canVerify(Algorithm.HS384));
    assertTrue(verifier.canVerify(Algorithm.HS512));

    assertFalse(verifier.canVerify(Algorithm.PS256));
    assertFalse(verifier.canVerify(Algorithm.PS384));
    assertFalse(verifier.canVerify(Algorithm.PS512));

    assertFalse(verifier.canVerify(Algorithm.RS256));
    assertFalse(verifier.canVerify(Algorithm.RS384));
    assertFalse(verifier.canVerify(Algorithm.RS512));
  }
}
