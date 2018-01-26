/*
 * Copyright (c) 2016-2018, Inversoft Inc., All Rights Reserved
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

package org.primeframework.jwt;

import org.primeframework.jwt.domain.RSAKeyPair;
import org.primeframework.jwt.rsa.RSAUtils;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.primeframework.jwt.rsa.PEMUtils.PKCS_8_PRIVATE_KEY_PREFIX;
import static org.primeframework.jwt.rsa.PEMUtils.PKCS_8_PRIVATE_KEY_SUFFIX;
import static org.primeframework.jwt.rsa.PEMUtils.X509_PUBLIC_KEY_PREFIX;
import static org.primeframework.jwt.rsa.PEMUtils.X509_PUBLIC_KEY_SUFFIX;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class JWTUtilsTest {
  @Test
  public void generateRSAKey() throws Exception {
    RSAKeyPair keyPair2048 = JWTUtils.generate2048RSAKeyPair();
    RSAPrivateKey privateKey2048 = RSAUtils.getPrivateKeyFromPEM(keyPair2048.privateKey);
    RSAPublicKey publicKey2048 = RSAUtils.getPublicKeyFromPEM(keyPair2048.publicKey);
    assertEquals(privateKey2048.getModulus().bitLength(), 2048);
    assertEquals(publicKey2048.getModulus().bitLength(), 2048);
    assertPrefix(keyPair2048.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair2048.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair2048.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair2048.publicKey, X509_PUBLIC_KEY_SUFFIX);

    // Now go backwards from the key to a PEM and assert they come out the same.
    String actualPrivateKey2048 = RSAUtils.getPEMFromPrivateKey(privateKey2048);
    String actualPublicKey2048 = RSAUtils.getPEMFromPublicKey(publicKey2048);
    assertEquals(actualPrivateKey2048, keyPair2048.privateKey);
    assertEquals(actualPublicKey2048, keyPair2048.publicKey);

    RSAKeyPair keyPair3072 = JWTUtils.generate3072RSAKeyPair();
    RSAPrivateKey privateKey3072 = RSAUtils.getPrivateKeyFromPEM(keyPair3072.privateKey);
    RSAPublicKey publicKey3072 = RSAUtils.getPublicKeyFromPEM(keyPair3072.publicKey);
    assertEquals(privateKey3072.getModulus().bitLength(), 3072);
    assertEquals(publicKey3072.getModulus().bitLength(), 3072);
    assertPrefix(keyPair3072.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair3072.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair3072.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair3072.publicKey, X509_PUBLIC_KEY_SUFFIX);

    RSAKeyPair keyPair4096 = JWTUtils.generate4096RSAKeyPair();
    RSAPrivateKey privateKey4096 = RSAUtils.getPrivateKeyFromPEM(keyPair4096.privateKey);
    RSAPublicKey publicKey4096 = RSAUtils.getPublicKeyFromPEM(keyPair4096.publicKey);
    assertEquals(privateKey4096.getModulus().bitLength(), 4096);
    assertEquals(publicKey4096.getModulus().bitLength(), 4096);
    assertPrefix(keyPair4096.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair4096.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair4096.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair4096.publicKey, X509_PUBLIC_KEY_SUFFIX);
  }

  @Test
  public void hmacSecretLengths() throws Exception {
    String hmac256 = JWTUtils.generateSHA256HMACSecret();
    assertEquals(hmac256.length(), 44);
    assertEquals(Base64.getDecoder().decode(hmac256.getBytes(StandardCharsets.UTF_8)).length, 32);

    String hmac384 = JWTUtils.generateSHA384HMACSecret();
    assertEquals(hmac384.length(), 64);
    assertEquals(Base64.getDecoder().decode(hmac384.getBytes(StandardCharsets.UTF_8)).length, 48);

    String hmac512 = JWTUtils.generateSHA512HMACSecret();
    assertEquals(hmac512.length(), 88);
    assertEquals(Base64.getDecoder().decode(hmac512.getBytes(StandardCharsets.UTF_8)).length, 64);
  }

  @Test
  public void rsaKeyLengths() throws Exception {
    RSAKeyPair keyPair2048 = JWTUtils.generate2048RSAKeyPair();
    String publicKey2048 = trimPublicKey(keyPair2048.publicKey);
    assertEquals(publicKey2048.length(), 392);

    RSAKeyPair keyPair3072 = JWTUtils.generate3072RSAKeyPair();
    String publicKey3072 = trimPublicKey(keyPair3072.publicKey);
    assertEquals(publicKey3072.length(), 564);

    RSAKeyPair keyPair4096 = JWTUtils.generate4096RSAKeyPair();
    String publicKey4096 = trimPublicKey(keyPair4096.publicKey);
    assertEquals(publicKey4096.length(), 736);
  }

  private void assertPrefix(String key, String prefix) {
    assertTrue(key.startsWith(prefix));
  }

  private void assertSuffix(String key, String suffix) {
    String trimmed = key.trim();
    assertTrue(trimmed.endsWith(suffix));
  }

  private String trimPublicKey(String publicKey) {
    int begin = publicKey.indexOf(X509_PUBLIC_KEY_PREFIX);
    int end = publicKey.indexOf(X509_PUBLIC_KEY_SUFFIX);
    return publicKey.substring(begin + X509_PUBLIC_KEY_PREFIX.length(), end).replaceAll("\\s", "");
  }
}
