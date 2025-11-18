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
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.pem.domain.PEM;
import org.testng.annotations.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class EdDSAVerifierTest extends BaseJWTTest {
  @Test
  public void canVerify() {
    Verifier verifier = EdDSAVerifier.newVerifier(getPath("ed_dsa_public_key.pem"));
    assertTrue(verifier.canVerify(Algorithm.EdDSA));
    PEM pem = PEM.decode(getPath("ed_dsa_public_key.pem"));
    EdDSAVerifier.newVerifier(pem.publicKey);

    Verifier verifier25519 = EdDSAVerifier.newVerifier(getPath("ed_dsa_ed25519_public_key.pem"));
    assertTrue(verifier25519.canVerify(Algorithm.EdDSA));

    Verifier verifier448 = EdDSAVerifier.newVerifier(getPath("ed_dsa_ed448_public_key.pem"));
    assertTrue(verifier448.canVerify(Algorithm.EdDSA));
  }

  @Test
  public void decodePrivateKey() throws Exception {
    List<String> privateKeys = List.of(
        "ed_dsa_ed448_private_key.pem",
        "eddsa_ed448_private_key.pem",
        "ed_dsa_ed25519_private_key.pem",
        "ed_dsa_private_key.pem"
    );

    // These keys do not contain a public key. However, the public key can be produced from the private key for EdDSA.
    for (String f : privateKeys) {
      String message = "For file [" + f + "]";
      String encodedPEM = new String(Files.readAllBytes(Paths.get("src/test/resources/" + f)));
      assertTrue(encodedPEM.contains(PEM.PKCS_8_PRIVATE_KEY_PREFIX), message);

      PEM pem = PEM.decode(encodedPEM);
      assertNotNull(pem.privateKey, message);
      assertEquals(pem.privateKey.getFormat(), "PKCS#8", message);
      assertNotNull(pem.publicKey, message);
      assertEquals(pem.publicKey.getFormat(), "X.509", message);
      String expectedAlgorithm = fipsEnabled ? (f.contains("ed448") ? "Ed448" : "Ed25519") : "EdDSA";
      assertEquals(pem.publicKey.getAlgorithm(), expectedAlgorithm, message);
    }

    // Private keys that contain a public key
    for (String f : List.of("ed_dsa_ed25519_private_key_pub.pem")) {
      String message = "For file [" + f + "]";
      String encodedPEM = new String(Files.readAllBytes(Paths.get("src/test/resources/" + f)));
      assertTrue(encodedPEM.contains(PEM.PKCS_8_PRIVATE_KEY_PREFIX), message);

      PEM pem = PEM.decode(encodedPEM);
      assertNotNull(pem.privateKey, message);
      assertEquals(pem.privateKey.getFormat(), "PKCS#8", message);
      assertNotNull(pem.publicKey, message);
      assertEquals(pem.publicKey.getFormat(), "X.509", message);
      String expectedAlgorithm = fipsEnabled ? "Ed25519" : "EdDSA";
      assertEquals(pem.publicKey.getAlgorithm(), expectedAlgorithm, message);
    }
  }

  @Test
  public void decodePublicKey() throws Exception {
    List<String> publicKeys = Arrays.asList(
        "ed_dsa_ed25519_public_key.pem",
        "ed_dsa_ed448_public_key.pem",
        "ed_dsa_public_key.pem");

    for (String f : publicKeys) {
      String message = "For file [" + f + "]";
      String encodedPEM = new String(Files.readAllBytes(Paths.get("src/test/resources/" + f)));
      assertTrue(encodedPEM.contains(PEM.X509_PUBLIC_KEY_PREFIX), message);
      assertTrue(encodedPEM.contains(PEM.X509_PUBLIC_KEY_SUFFIX), message);

      PEM pem = PEM.decode(encodedPEM);
      assertNotNull(pem.publicKey, message);
      assertEquals(pem.publicKey.getFormat(), "X.509", message);
    }
  }
}
