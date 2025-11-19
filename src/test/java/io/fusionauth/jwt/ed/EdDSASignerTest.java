/*
 * Copyright (c) 2025, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwt.ed;

import io.fusionauth.jwt.BaseJWTTest;
import io.fusionauth.jwt.MissingVerifierException;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.pem.domain.PEM;
import org.testng.annotations.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * @author Daniel DeGroff
 */
public class EdDSASignerTest extends BaseJWTTest {
  @Test
  public void signAndVerify() throws Exception {
    JWT jwt = new JWT().setSubject("1234567890");

    // Sign the JWT
    Signer signer = EdDSASigner.newSigner(new String(Files.readAllBytes(Paths.get("src/test/resources/ed_dsa_private_key.pem"))));
    String encodedJWT = JWT.getEncoder().encode(jwt, signer);

    // Verify the JWT
    Verifier verifier = EdDSAVerifier.newVerifier(Paths.get("src/test/resources/ed_dsa_public_key.pem"));
    JWT actual = JWT.getDecoder().decode(encodedJWT, verifier);

    assertEquals(actual.subject, jwt.subject);
    assertEquals(actual.header.algorithm.name(), "Ed25519");

    Verifier verifier448 = EdDSAVerifier.newVerifier(getPath("ed_dsa_ed448_public_key.pem"));
    try {
      // You can't double stamp a triple stamp, or verify a JWT signed using Ed25519 with an Ed448 verifier.
      JWT.getDecoder().decode(encodedJWT, verifier448);
      fail("Expected an exception to be thrown.");
    } catch (Exception e) {
      assertTrue(e instanceof MissingVerifierException);
      assertEquals(e.getMessage(), "No Verifier has been provided for verify a signature signed using [Ed25519]");
    }
  }

  @Test
  public void test_private_pem_parsing() {
    // Key as string
    assertNotNull(EdDSASigner.newSigner(readFile("ed_dsa_ed25519_private_key.pem")));
    assertNotNull(EdDSASigner.newSigner(readFile("ed_dsa_ed448_private_key.pem")));

    // Key as object
    assertNotNull(EdDSASigner.newSigner(PEM.decode(getPath("ed_dsa_ed25519_private_key.pem")).privateKey));
    assertNotNull(EdDSASigner.newSigner(PEM.decode(getPath("ed_dsa_ed448_private_key.pem")).privateKey));

    // Add kid

    // Key as string
    assertNotNull(EdDSASigner.newSigner(readFile("ed_dsa_ed25519_private_key.pem"), "abc").getKid(), "abc");
    assertNotNull(EdDSASigner.newSigner(readFile("ed_dsa_ed448_private_key.pem"), "abc").getKid(), "abc");

    // Key as object
    assertNotNull(EdDSASigner.newSigner(PEM.decode(getPath("ed_dsa_ed25519_private_key.pem")).privateKey, "abc").getKid(), "abc");
    assertNotNull(EdDSASigner.newSigner(PEM.decode(getPath("ed_dsa_ed448_private_key.pem")).privateKey, "abc").getKid(), "abc");
  }
}
