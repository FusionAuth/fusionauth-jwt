/*
 * Copyright (c) 2018-2019, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

package io.fusionauth.jwt.ec;

import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

import io.fusionauth.jwt.BaseJWTTest;
import io.fusionauth.jwt.MissingPublicKeyException;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.hmac.HMAC;
import io.fusionauth.jwt.rsa.RSA;
import io.fusionauth.pem.domain.PEM;
import org.testng.Assert;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class ECVerifierTest extends BaseJWTTest {
  @Test
  public void test_public_pem_parsing() {
    Arrays.asList(
              "ec_public_key_p_256.pem",
              "ec_public_key_p_384.pem",
              "ec_public_key_p_521.pem")
          .forEach(fileName -> {
            // Take a Path arg
            assertECVerifier(ECVerifier.newVerifier(getPath(fileName)));
            // Take a String arg
            assertECVerifier(ECVerifier.newVerifier(readFile(fileName)));
            // Take a byte[] arg
            assertECVerifier(ECVerifier.newVerifier(readFile(fileName).getBytes(StandardCharsets.UTF_8)));
            // Take a public key arg
            assertECVerifier(ECVerifier.newVerifier((ECPublicKey) PEM.decode(readFile(fileName)).getPublicKey()));
          });

    // Public key parsing fails with private keys w/out an encoded public key
    Arrays.asList(
              "ec_private_key_p_256.pem",
              "ec_private_key_p_384.pem",
              "ec_private_key_p_521.pem")
          .forEach(this::assertFailed);

    // Public key parsing works with private keys when the private key contains a public key
    Arrays.asList(
              "ec_private_prime256v1_p_256_openssl.pem",
              "ec_private_prime256v1_p_256_openssl_pkcs8.pem",
              "ec_private_secp384r1_p_384_openssl.pem",
              "ec_private_secp384r1_p_384_openssl_pkcs8.pem",
              "ec_private_secp521r1_p_512_openssl.pem",
              "ec_private_secp521r1_p_512_openssl_pkcs8.pem")
          .forEach(fileName -> {
            // Take a Path arg
            assertECVerifier(ECVerifier.newVerifier(getPath(fileName)));
            // Take a String arg
            assertECVerifier(ECVerifier.newVerifier(readFile(fileName)));
            // Take a byte[] arg
            assertECVerifier(ECVerifier.newVerifier(readFile(fileName).getBytes(StandardCharsets.UTF_8)));
            // Take a public key arg
            assertECVerifier(ECVerifier.newVerifier((ECPublicKey) PEM.decode(readFile(fileName)).getPublicKey()));
          });

  }

  private void assertECVerifier(Verifier verifier) {
    assertTrue(verifier.canVerify(EC.ES256));
    assertTrue(verifier.canVerify(EC.ES384));
    assertTrue(verifier.canVerify(EC.ES512));

    assertFalse(verifier.canVerify(HMAC.HS256));
    assertFalse(verifier.canVerify(HMAC.HS384));
    assertFalse(verifier.canVerify(HMAC.HS512));

    assertFalse(verifier.canVerify(RSA.PS256));
    assertFalse(verifier.canVerify(RSA.PS384));
    assertFalse(verifier.canVerify(RSA.PS512));

    assertFalse(verifier.canVerify(RSA.RS256));
    assertFalse(verifier.canVerify(RSA.RS384));
    assertFalse(verifier.canVerify(RSA.RS512));

  }

  private void assertFailed(String fileName) {
    try {
      ECVerifier.newVerifier(readFile(fileName));
      Assert.fail("Expected [InvalidParameterException] exception");
    } catch (InvalidParameterException e) {
      assertEquals(e.getMessage(), "Unexpected Public Key Format", "[" + fileName + "]");
    } catch (MissingPublicKeyException e) {
      assertEquals(e.getMessage(), "The provided PEM encoded string did not contain a public key.");
    } catch (Exception e) {
      Assert.fail("Unexpected exception when parsing file [" + fileName + "]", e);
    }
  }
}
