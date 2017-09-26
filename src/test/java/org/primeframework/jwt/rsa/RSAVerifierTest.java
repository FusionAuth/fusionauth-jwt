/*
 * Copyright (c) 2017, Inversoft Inc., All Rights Reserved
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

package org.primeframework.jwt.rsa;

import org.primeframework.jwt.BaseTest;
import org.primeframework.jwt.Verifier;
import org.primeframework.jwt.domain.Algorithm;
import org.primeframework.jwt.domain.InvalidKeyLengthException;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidParameterException;
import java.util.Arrays;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class RSAVerifierTest extends BaseTest {
  @Test
  public void test_private_pem_parsing() throws Exception {
    RSASigner.newSHA256Signer(readFile("rsa_private_key_2048.pem"));
    RSASigner.newSHA256Signer(readFile("rsa_private_key_2048_with_meta.pem"));
    RSASigner.newSHA256Signer(readFile("rsa_private_key_3072.pem"));
    RSASigner.newSHA256Signer(readFile("rsa_private_key_4096.pem"));
  }

  @Test
  public void test_public_pem_parsing() throws Exception {
    Arrays.asList(
        "rsa_public_certificate_2048.pem",
        "rsa_public_key_2048.pem",
        "rsa_public_key_2048_with_meta.pem",
        "rsa_public_key_3072.pem",
        "rsa_public_key_4096.pem")
        .forEach(fileName -> assertRSAVerifier(RSAVerifier.newVerifier(readFile(fileName))));

    // Public key parsing fails with private keys
    Arrays.asList(
        "rsa_private_key_2048.pem",
        "rsa_private_key_2048_with_meta.pem",
        "rsa_private_key_3072.pem",
        "rsa_private_key_4096.pem")
        .forEach(this::assertFailed);
  }

  @Test
  public void test_rsa_1024_pem() throws Exception {
    try {
      RSAVerifier.newVerifier(new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_1024.pem"))));
      Assert.fail("Expected [InvalidKeyLengthException] exception");
    } catch (InvalidKeyLengthException ignore) {
    } catch (Exception e) {
      Assert.fail("Unexpected exception", e);
    }
  }

  private void assertFailed(String fileName) {
    try {
      RSAVerifier.newVerifier(readFile(fileName));
      Assert.fail("Expected [InvalidParameterException] exception");
    } catch (InvalidParameterException e) {
      assertEquals(e.getMessage(), "Unexpected Public Key Format", "[" + fileName + "]");
    } catch (Exception e) {
      Assert.fail("Unexpected exception when parsing file [" + fileName + "]", e);
    }
  }

  private void assertRSAVerifier(Verifier verifier) {
    assertTrue(verifier.canVerify(Algorithm.RS256));
    assertTrue(verifier.canVerify(Algorithm.RS384));
    assertTrue(verifier.canVerify(Algorithm.RS512));
    assertFalse(verifier.canVerify(Algorithm.HS256));
    assertFalse(verifier.canVerify(Algorithm.HS384));
    assertFalse(verifier.canVerify(Algorithm.HS512));
  }
}
