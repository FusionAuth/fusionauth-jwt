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

import io.fusionauth.BaseTest;
import io.fusionauth.pem.domain.PEM;
import org.testng.annotations.Test;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class PEMEncoderTest extends BaseTest {
  @Test
  public void ec() throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
    keyPairGenerator.initialize(256);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    String encodedPublicKey = PEM.encode(keyPair.getPublic());
    assertNotNull(encodedPublicKey);
    assertTrue(encodedPublicKey.startsWith(PEM.X509_PUBLIC_KEY_PREFIX));
    assertTrue(encodedPublicKey.endsWith(PEM.X509_PUBLIC_KEY_SUFFIX));

    String encodedPrivateKey = PEM.encode(keyPair.getPrivate());
    assertNotNull(encodedPrivateKey);
    assertTrue(encodedPrivateKey.startsWith(PEM.PKCS_8_PRIVATE_KEY_PREFIX));
    assertTrue(encodedPrivateKey.endsWith(PEM.PKCS_8_PRIVATE_KEY_SUFFIX));

    // Since we built our own key pair, the private key will not contain the public key
    PEM pem = PEM.decode(encodedPrivateKey);
    assertNotNull(pem.getPrivateKey());
    assertNull(pem.getPublicKey());

    // Try again, but provide both keys to encode into the PEM
    String encodedPrivateKey2 = PEM.encode(keyPair.getPrivate(), keyPair.getPublic());
    assertNotNull(encodedPrivateKey2);
    PEM pem2 = PEM.decode(encodedPrivateKey2);
    assertNotNull(pem2.getPrivateKey());
    assertNotNull(pem2.getPublicKey());
  }

  @Test
  public void ec_backAndForth() throws Exception {
    // Start with openSSL PKCS#8 private key and X.509 public key
    String expectedPrivate = new String(Files.readAllBytes(Paths.get("src/test/resources/ec_private_prime256v1_p_256_openssl_pkcs8.pem"))).trim();
    String expectedPublic = new String(Files.readAllBytes(Paths.get("src/test/resources/ec_public_prime256v1_p_256_openssl.pem"))).trim();

    // Decode the private key to ensure we get both private and public keys out of the private PEM
    PEM pem = PEM.decode(expectedPrivate);
    assertNotNull(pem);
    assertNotNull(pem.getPrivateKey());
    assertNotNull(pem.getPublicKey());

    // Ensure the public key we extracted is correct
    ECPublicKey publicKey = pem.getPublicKey();
    assertEquals(publicKey.getW().getAffineX(), new BigInteger("7676a6ec4ee9058b59c11c8e3038e02979ccd47fca46f20fa1b130d379d9038f", 16));
    assertEquals(publicKey.getW().getAffineY(), new BigInteger("8abdebcea6831f8ec07c1b4f95ceb7eb0d121cb3d23c54cfa572fba97a0de510", 16));

    // Re-encode the private key to PEM PKCS#8 format and ensure it equals the original
    String encodedPrivateKey = PEM.encode((Key) pem.getPrivateKey());
    assertEquals(encodedPrivateKey, expectedPrivate);

    // Re-encode the public key to PEM X.509 format and ensure it equals the original
    String encodedPublicKey = PEM.encode((Key) pem.getPublicKey());
    assertEquals(encodedPublicKey, expectedPublic);
  }

  @Test
  public void rsa() throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    assertNotNull(keyPair.getPublic());
    assertNotNull(keyPair.getPrivate());

    String encodedPublicKey = PEM.encode(keyPair.getPublic());
    assertNotNull(encodedPublicKey);
    assertTrue(encodedPublicKey.startsWith(PEM.X509_PUBLIC_KEY_PREFIX));
    assertTrue(encodedPublicKey.endsWith(PEM.X509_PUBLIC_KEY_SUFFIX));

    String encodedPrivateKey = PEM.encode(keyPair.getPrivate());
    assertNotNull(encodedPrivateKey);
    assertTrue(encodedPrivateKey.startsWith(PEM.PKCS_8_PRIVATE_KEY_PREFIX));
    assertTrue(encodedPrivateKey.endsWith(PEM.PKCS_8_PRIVATE_KEY_SUFFIX));

    // Since the public RSA modulus and  public exponent are always included in the private key, they should
    // be contained in the generated PEM
    PEM pem = PEM.decode(encodedPrivateKey);
    assertNotNull(pem.getPrivateKey());
    assertNotNull(pem.getPublicKey());
  }

  @Test
  public void rsa_backAndForth_pkcs_1() throws Exception {
    // Start externally created PKCS#1 private key and X.509 public key
    String expectedPrivate_pkcs_1 = new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_2048_pkcs_1_control.pem"))).trim();
    String expectedPrivate_pkcs_8 = new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_2048_pkcs_8_control.pem"))).trim();
    String expectedPublic = new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_2048_x509_control.pem")));

    // Decode the private key to ensure we get both private and public keys out of the private PEM
    PEM pem = PEM.decode(expectedPrivate_pkcs_1);
    assertNotNull(pem);
    assertNotNull(pem.getPrivateKey());
    assertNotNull(pem.getPublicKey());

    // Ensure the public key we extracted is correct
    RSAPublicKey publicKey = pem.getPublicKey();
    String expectedModulus = "dd95ab518d18e8828dd6a238061c51d82ee81d516018f624777f2e1aad6340d4aa12f24570df770989b5ebf1bbf05005296ab0b096f75b1fa76f10e7e8bb4fe008542c1d47d0ad20eff8cb9250c01ef23cca138a96fa32bec5053d6b4dc652728792495ef90d295ff83a8d767baf5ff100ae43a36910f97e712bd722a518042b";
    assertEquals(publicKey.getModulus(), new BigInteger(expectedModulus, 16));
    assertEquals(publicKey.getPublicExponent(), BigInteger.valueOf(0x10001));
    assertEquals(publicKey.getPublicExponent(), BigInteger.valueOf(65537));

    // Re-encode the private key which started as PKCS#1 to PEM PKCS#8 format
    String encodedPrivateKey_pkcs_8 = PEM.encode((Key) pem.getPrivateKey());
    assertTrue(encodedPrivateKey_pkcs_8.startsWith(PEM.PKCS_8_PRIVATE_KEY_PREFIX));
    // The PKCS#1 will not equal the PKCS#8 key
    assertNotEquals(encodedPrivateKey_pkcs_8, expectedPrivate_pkcs_1);
    assertEquals(encodedPrivateKey_pkcs_8, expectedPrivate_pkcs_8);

    // Re-encode the public key to PEM X.509 format and ensure it equals the original
    String encodedPublicKey = PEM.encode((Key) pem.getPublicKey());
    assertEquals(encodedPublicKey, expectedPublic);
  }

  @Test
  public void rsa_backAndForth_pkcs_8() throws Exception {
    // Start externally created PKCS#1 private key and X.509 public key
    String expectedPrivate = new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_2048_pkcs_8_control.pem"))).trim();
    String expectedPublic = new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_2048_x509_control.pem"))).trim();

    // Decode the private key to ensure we get both private and public keys out of the private PEM
    PEM pem = PEM.decode(expectedPrivate);
    assertNotNull(pem);
    assertNotNull(pem.getPrivateKey());
    assertNotNull(pem.getPublicKey());

    // Ensure the public key we extracted is correct
    RSAPublicKey publicKey = pem.getPublicKey();
    String expectedModulus = "dd95ab518d18e8828dd6a238061c51d82ee81d516018f624777f2e1aad6340d4aa12f24570df770989b5ebf1bbf05005296ab0b096f75b1fa76f10e7e8bb4fe008542c1d47d0ad20eff8cb9250c01ef23cca138a96fa32bec5053d6b4dc652728792495ef90d295ff83a8d767baf5ff100ae43a36910f97e712bd722a518042b";
    assertEquals(publicKey.getModulus(), new BigInteger(expectedModulus, 16));
    assertEquals(publicKey.getPublicExponent(), BigInteger.valueOf(0x10001));
    assertEquals(publicKey.getPublicExponent(), BigInteger.valueOf(65537));

    // Re-encode the private to PEM PKCS#8 format
    String encodedPrivateKey_pkcs_8 = PEM.encode((Key) pem.getPrivateKey());
    assertTrue(encodedPrivateKey_pkcs_8.startsWith(PEM.PKCS_8_PRIVATE_KEY_PREFIX));
    assertEquals(encodedPrivateKey_pkcs_8, expectedPrivate);

    // Re-encode the public key to PEM X.509 format and ensure it equals the original
    String encodedPublicKey = PEM.encode((Key) pem.getPublicKey());
    assertEquals(encodedPublicKey, expectedPublic);
  }
}
