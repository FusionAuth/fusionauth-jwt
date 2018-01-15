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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Helper to generate new HMAC secrets or RSA public / private key pairs.
 *
 * @author Daniel DeGroff
 */
public class JWTUtils {

  /**
   * Generate a new public / private key pair using a 2048 bit RSA key. This is the minimum key length for use with an
   * RSA signing scheme for JWT.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static RSAKeyPair generate2048RSAKeyPair() {
    return generateRSAKeyPair(2048);
  }

  /**
   * Generate a new public / private key pair using a 3072 bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static RSAKeyPair generate3072RSAKeyPair() {
    return generateRSAKeyPair(3072);
  }

  /**
   * Generate a new public / private key pair using a 4096 bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static RSAKeyPair generate4096RSAKeyPair() {
    return generateRSAKeyPair(4096);
  }

  /**
   * Generate a 32 byte (256 bit) HMAC secret for use with a SHA-256 hash.
   *
   * @return a secret for use with an HMAC signing and verification scheme.
   */
  public static String generateSHA256HMACSecret() {
    byte[] buffer = new byte[32];
    new SecureRandom().nextBytes(buffer);
    return Base64.getEncoder().encodeToString(buffer);
  }

  /**
   * Generate a 48 byte (384 bit) HMAC secret for use with a SHA-384 hash.
   *
   * @return a secret for use with an HMAC signing and verification scheme.
   */
  public static String generateSHA384HMACSecret() {
    byte[] buffer = new byte[48];
    new SecureRandom().nextBytes(buffer);
    return Base64.getEncoder().encodeToString(buffer);
  }

  /**
   * Generate a 64 byte (512 bit) HMAC secret for use with a SHA-512 hash.
   *
   * @return a secret for use with an HMAC signing and verification scheme.
   */
  public static String generateSHA512HMACSecret() {
    byte[] buffer = new byte[64];
    new SecureRandom().nextBytes(buffer);
    return Base64.getEncoder().encodeToString(buffer);
  }

  /**
   * Generate a new Public / Private keypair with a key size of the provided length.
   *
   * @param keySize the length of the key in bits
   * @return a public and private key in PEM format.
   */
  private static RSAKeyPair generateRSAKeyPair(int keySize) {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(keySize);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      String privateKey = RSAUtils.getPEMFromPrivateKey(keyPair.getPrivate());
      String publicKey = RSAUtils.getPEMFromPublicKey(keyPair.getPublic());
      return new RSAKeyPair(privateKey, publicKey);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
