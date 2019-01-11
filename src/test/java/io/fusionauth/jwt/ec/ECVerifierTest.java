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

import io.fusionauth.jwt.BaseTest;
import io.fusionauth.jwt.MissingPublicKeyException;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.Algorithm;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.InvalidParameterException;
import java.util.Arrays;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class ECVerifierTest extends BaseTest {
  @Test
  public void test_public_pem_parsing() {
    Arrays.asList(
        "ec_public_key_p_256.pem",
        "ec_public_key_p_384.pem",
        "ec_public_key_p_521.pem")
          .forEach(fileName -> assertECVerifier(ECVerifier.newVerifier(readFile(fileName))));

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
          .forEach(fileName -> assertECVerifier(ECVerifier.newVerifier(readFile(fileName))));
  }

  private void assertECVerifier(Verifier verifier) {
    assertTrue(verifier.canVerify(Algorithm.ES256));
    assertTrue(verifier.canVerify(Algorithm.ES384));
    assertTrue(verifier.canVerify(Algorithm.ES512));
    assertFalse(verifier.canVerify(Algorithm.RS256));
    assertFalse(verifier.canVerify(Algorithm.RS384));
    assertFalse(verifier.canVerify(Algorithm.RS512));
    assertFalse(verifier.canVerify(Algorithm.HS256));
    assertFalse(verifier.canVerify(Algorithm.HS384));
    assertFalse(verifier.canVerify(Algorithm.HS512));
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
