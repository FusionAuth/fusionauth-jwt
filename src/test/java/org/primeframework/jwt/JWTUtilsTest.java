/*
 * Copyright (c) 2016, Inversoft Inc., All Rights Reserved
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

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class JWTUtilsTest {
  @Test
  public void generateHMACSecrets() throws Exception {
    String hmac256 = JWTUtils.generateSHA256HMACSecret();
    assertEquals(Base64.getDecoder().decode(hmac256.getBytes()).length, 32);

    String hmac384 = JWTUtils.generateSHA384HMACSecret();
    assertEquals(Base64.getDecoder().decode(hmac384.getBytes()).length, 48);

    String hmac512 = JWTUtils.generateSHA512HMACSecret();
    assertEquals(Base64.getDecoder().decode(hmac512.getBytes()).length, 64);
  }

  @Test
  public void generateRSAKey() throws Exception {
    RSAKeyPair keyPair2048 = JWTUtils.generate2048RSAKeyPair();
    RSAPrivateKey privateKey2048 = RSAUtils.getPrivateKeyFromPEM(keyPair2048.privateKey);
    RSAPublicKey publicKey2048 = RSAUtils.getPublicKeyFromPEM(keyPair2048.publicKey);
    assertEquals(privateKey2048.getModulus().bitLength(), 2048);
    assertEquals(publicKey2048.getModulus().bitLength(), 2048);
    assertTrue(keyPair2048.privateKey.contains("BEGIN PRIVATE KEY"));
    assertTrue(keyPair2048.publicKey.contains("BEGIN PUBLIC KEY"));

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
    assertTrue(keyPair3072.privateKey.contains("BEGIN PRIVATE KEY"));
    assertTrue(keyPair3072.publicKey.contains("BEGIN PUBLIC KEY"));

    RSAKeyPair keyPair4096 = JWTUtils.generate4096RSAKeyPair();
    RSAPrivateKey privateKey4096 = RSAUtils.getPrivateKeyFromPEM(keyPair4096.privateKey);
    RSAPublicKey publicKey4096 = RSAUtils.getPublicKeyFromPEM(keyPair4096.publicKey);
    assertEquals(privateKey4096.getModulus().bitLength(), 4096);
    assertEquals(publicKey4096.getModulus().bitLength(), 4096);
    assertTrue(keyPair4096.privateKey.contains("BEGIN PRIVATE KEY"));
    assertTrue(keyPair4096.publicKey.contains("BEGIN PUBLIC KEY"));
  }
}
