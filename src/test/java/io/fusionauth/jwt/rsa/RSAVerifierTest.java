/*
 * Copyright (c) 2017-2022, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwt.rsa;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import io.fusionauth.jwt.BaseJWTTest;
import io.fusionauth.jwt.InvalidKeyLengthException;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.ec.EC;
import io.fusionauth.jwt.hmac.HMAC;
import io.fusionauth.pem.domain.PEM;
import org.testng.Assert;
import org.testng.annotations.Test;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class RSAVerifierTest extends BaseJWTTest {
  @Test
  public void test_public_pem_parsing() {
    Arrays.asList(
              "rsa_certificate_2048.pem",
              "rsa_public_key_2047.pem",
              "rsa_public_key_2048.pem",
              "rsa_public_key_2048_with_meta.pem",
              "rsa_public_key_3072.pem",
              "rsa_public_key_4096.pem")
          .forEach(fileName -> {
            // Take a String arg
            assertRSAVerifier(RSAVerifier.newVerifier(getPath(fileName)));
            // Take a Path arg
            assertRSAVerifier(RSAVerifier.newVerifier(readFile(fileName)));
            // Take a byte[] arg
            assertRSAVerifier(RSAVerifier.newVerifier(readFile(fileName).getBytes(StandardCharsets.UTF_8)));
            // Take a public key arg
            assertRSAVerifier(RSAVerifier.newVerifier((RSAPublicKey) PEM.decode(readFile(fileName)).getPublicKey()));
          });

    // Public key parsing also works with private keys since the public key is encoded in the private
    Arrays.asList(
              "rsa_private_key_2048.pem",
              "rsa_private_key_2048_with_meta.pem",
              "rsa_private_key_3072.pem",
              "rsa_private_key_4096.pem")
          .forEach((fileName -> {
            // Take a String arg
            assertRSAVerifier(RSAVerifier.newVerifier(getPath(fileName)));
            // Take a Path arg
            assertRSAVerifier(RSAVerifier.newVerifier(readFile(fileName)));
            // Take a byte[] arg
            assertRSAVerifier(RSAVerifier.newVerifier(readFile(fileName).getBytes(StandardCharsets.UTF_8)));
            // Take a public key arg
            assertRSAVerifier(RSAVerifier.newVerifier((RSAPublicKey) PEM.decode(readFile(fileName)).getPublicKey()));
          }));
  }

  @Test
  public void test_rsa_1024_pem() {
    try {
      RSAVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_1024.pem"))));
      Assert.fail("Expected [InvalidKeyLengthException] exception");
    } catch (InvalidKeyLengthException ignore) {
    } catch (Exception e) {
      Assert.fail("Unexpected exception", e);
    }
  }

  private void assertRSAVerifier(Verifier verifier) {
    assertFalse(verifier.canVerify(EC.ES256));
    assertFalse(verifier.canVerify(EC.ES384));
    assertFalse(verifier.canVerify(EC.ES512));

    assertFalse(verifier.canVerify(HMAC.HS256));
    assertFalse(verifier.canVerify(HMAC.HS384));
    assertFalse(verifier.canVerify(HMAC.HS512));

    assertFalse(verifier.canVerify(RSA.PS256));
    assertFalse(verifier.canVerify(RSA.PS384));
    assertFalse(verifier.canVerify(RSA.PS512));

    assertTrue(verifier.canVerify(RSA.RS256));
    assertTrue(verifier.canVerify(RSA.RS384));
    assertTrue(verifier.canVerify(RSA.RS512));
  }
}
