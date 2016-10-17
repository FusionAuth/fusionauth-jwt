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
import org.testng.annotations.Test;

import java.util.Base64;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class JWTUtilsTest {
  @Test
  public void hmac() throws Exception {
    String hmac256 = JWTUtils.generateSHA256HMACSecret();
    assertEquals(Base64.getDecoder().decode(hmac256.getBytes()).length, 32);

    String hmac512 = JWTUtils.generateSHA512HMACSecret();
    assertEquals(Base64.getDecoder().decode(hmac512.getBytes()).length, 64);
  }

  @Test
  public void rsa() throws Exception {
    RSAKeyPair keyPair2048 = JWTUtils.generate2048RSAKeyPair();
    assertTrue(keyPair2048.privateKey.contains("RSA PRIVATE KEY"));
    assertTrue(keyPair2048.publicKey.contains("RSA PUBLIC KEY"));

    RSAKeyPair keyPair3072 = JWTUtils.generate3072RSAKeyPair();
    assertTrue(keyPair3072.privateKey.contains("RSA PRIVATE KEY"));
    assertTrue(keyPair3072.publicKey.contains("RSA PUBLIC KEY"));

    RSAKeyPair keyPair4096 = JWTUtils.generate4096RSAKeyPair();
    assertTrue(keyPair4096.privateKey.contains("RSA PRIVATE KEY"));
    assertTrue(keyPair4096.publicKey.contains("RSA PUBLIC KEY"));
  }
}
