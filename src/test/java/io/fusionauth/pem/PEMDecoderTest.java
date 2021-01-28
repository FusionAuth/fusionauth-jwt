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

package io.fusionauth.pem;

import io.fusionauth.pem.domain.PEM;
import org.testng.annotations.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class PEMDecoderTest {
  @Test
  public void inputs() throws Exception {
    // Ensure there are no explosions, loading the PEM from a Path, bytes and a String
    assertNotNull(PEM.decode(Paths.get("src/test/resources/ec_public_key_p_256.pem")));
    assertNotNull(PEM.decode(Files.readAllBytes(Paths.get("src/test/resources/ec_public_key_p_256.pem"))));
    assertNotNull(PEM.decode(new String(Files.readAllBytes(Paths.get("src/test/resources/ec_public_key_p_256.pem")))));
  }

  @Test
  public void private_ec() throws Exception {
    // not encapsulated in PKCS#8, the PEM decoder should do this for us.
    List<String> filesIncludingPublicKey = Arrays.asList(
        "ec_private_prime256v1_p_256_openssl.pem",
        "ec_private_secp384r1_p_384_openssl.pem",
        "ec_private_secp521r1_p_512_openssl.pem");

    for (String f : filesIncludingPublicKey) {
      String message = "For file [" + f + "]";
      String encodedPEM = new String(Files.readAllBytes(Paths.get("src/test/resources/" + f)));
      assertTrue(encodedPEM.contains(PEM.EC_PRIVATE_KEY_PREFIX), message);

      PEM pem = PEM.decode(encodedPEM);
      assertNotNull(pem.privateKey, message);
      assertEquals(pem.privateKey.getFormat(), "PKCS#8", message);
      assertNotNull(pem.publicKey, message);
      assertEquals(pem.publicKey.getFormat(), "X.509", message);
    }
  }

  @Test
  public void private_pkcs_8() throws Exception {
    List<String> filesIncludingPublicKey = Arrays.asList(
        "ec_private_key_control.pem",
        "ec_private_prime256v1_p_256_openssl_pkcs8.pem",
        "ec_private_secp384r1_p_384_openssl_pkcs8.pem",
        "ec_private_secp521r1_p_512_openssl_pkcs8.pem",
        "rsa_private_key_2048_pkcs_8_control.pem",
        "rsa_private_key_3072.pem");

    for (String f : filesIncludingPublicKey) {
      String message = "For file [" + f + "]";
      String encodedPEM = new String(Files.readAllBytes(Paths.get("src/test/resources/" + f)));
      assertTrue(encodedPEM.contains(PEM.PKCS_8_PRIVATE_KEY_PREFIX), message);

      PEM pem = PEM.decode(encodedPEM);
      assertNotNull(pem.privateKey, message);
      assertEquals(pem.privateKey.getFormat(), "PKCS#8", message);
      assertNotNull(pem.publicKey, message);
      assertEquals(pem.publicKey.getFormat(), "X.509", message);
    }

    // These keys do not contain a public key
    List<String> filesDoNotIncludePublicKey = Arrays.asList(
        "ec_private_key_p_256.pem",
        "ec_private_key_p_384.pem",
        "ec_private_key_p_521.pem");

    for (String f : filesDoNotIncludePublicKey) {
      String message = "For file [" + f + "]";
      String encodedPEM = new String(Files.readAllBytes(Paths.get("src/test/resources/" + f)));
      assertTrue(encodedPEM.contains(PEM.PKCS_8_PRIVATE_KEY_PREFIX), message);

      PEM pem = PEM.decode(encodedPEM);
      assertNotNull(pem.privateKey, message);
      assertNull(pem.publicKey, message);
    }
  }

  @Test
  public void private_rsa_pkcs_1() throws Exception {
    List<String> files = Arrays.asList(
        "rsa_private_key_2048.pem",
        "rsa_private_key_2048_pkcs_1.pem",
        "rsa_private_key_4096_pkcs_1.pem",
        "rsa_private_key_2048_pkcs_1_control.pem",
        "rsa_private_key_2048_with_meta.pem",
        "rsa_private_key_4096.pem",
        "rsa_private_key_2048_RS256_control.pem");

    for (String f : files) {
      String message = "For file [" + f + "]";
      String encodedPEM = new String(Files.readAllBytes(Paths.get("src/test/resources/" + f)));
      assertTrue(encodedPEM.contains(PEM.PKCS_1_PRIVATE_KEY_PREFIX), message);

      PEM pem = PEM.decode(encodedPEM);
      assertNotNull(pem.privateKey, message);
      // The result will always be in a PKCS#8 format even when the input is PKCS#1
      assertEquals(pem.privateKey.getFormat(), "PKCS#8", message);
      assertNotNull(pem.publicKey, message);
      assertEquals(pem.publicKey.getFormat(), "X.509", message);
    }
  }

  @Test
  public void certificates() throws Exception {
    List<String> files = Arrays.asList(
        "rsa_certificate_1024.pem",
        "rsa_certificate_2048.pem"
    );

    for (String f : files) {
      String message = "For file [" + f + "]";
      String encodedPEM = new String(Files.readAllBytes(Paths.get("src/test/resources/" + f)));
      assertTrue(encodedPEM.contains(PEM.X509_CERTIFICATE_PREFIX), message);

      PEM pem = PEM.decode(encodedPEM);
      assertNull(pem.privateKey, message);
      assertNotNull(pem.certificate, message);
      assertNotNull(pem.publicKey, message);
      assertEquals(pem.publicKey.getFormat(), "X.509", message);
      assertEquals(pem.certificate.getType(), "X.509", message);
    }
  }

  @Test
  public void public_x509() throws Exception {
    List<String> files = Arrays.asList(
        "ec_public_key_p_256.pem",
        "ec_public_key_p_256_control.pem",
        "rsa_public_key_2048_x509.pem",
        "rsa_public_key_4096_x509.pem",
        "rsa_public_key_2048_x509_control.pem",
        "rsa_public_key_2048_RS256_control.pem");

    for (String f : files) {
      String message = "For file [" + f + "]";
      String encodedPEM = new String(Files.readAllBytes(Paths.get("src/test/resources/" + f)));
      assertTrue(encodedPEM.contains(PEM.X509_PUBLIC_KEY_PREFIX), message);

      PEM pem = PEM.decode(encodedPEM);
      assertNull(pem.privateKey, message);
      assertNotNull(pem.publicKey, message);
      assertEquals(pem.publicKey.getFormat(), "X.509", message);
    }
  }
}
