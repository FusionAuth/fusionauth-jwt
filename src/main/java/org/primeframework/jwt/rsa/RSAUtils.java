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

package org.primeframework.jwt.rsa;

import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * RSA Key Helper.
 *
 * @author Daniel DeGroff
 */
public class RSAUtils {
  // RSA Private Key file (PKCS#1) End Tag
  private static final String PKCS_1_PRIVATE_KEY_END = "-----END RSA PRIVATE KEY";

  // RSA Private Key file (PKCS#1)  Start Tag
  private static final String PKCS_1_PRIVATE_KEY_START = "BEGIN RSA PRIVATE KEY-----";

  // RSA Public Key file (PKCS#1)  Start Tag
  private static final String PKCS_1_PUBLIC_KEY_START = "BEGIN RSA PUBLIC KEY-----";

  // RSA Public Key file (PKCS#1)  Start Tag
  private static final String PKCS_1_PUBLIC_KEY_END = "-----END RSA PUBLIC KEY";

  /**
   * Return a Private Key from the provided private key in PEM format.
   *
   * @param privateKey the private key in string format.
   * @return a private key
   */
  public static RSAPrivateKey getPrivateKeyFromPEM(String privateKey) {
    try {
      KeySpec keySpec = getRSAPrivateKeySpec(privateKey);
      return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    } catch (GeneralSecurityException | IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Return a PublicKey from the public key pem string.
   *
   * @param publicKey the public in PEM format.
   * @return the public key
   */
  public static RSAPublicKey getPublicKeyFromPEM(String publicKey) {
    try {
      KeySpec keySpec = getPublicKeySpec(publicKey);
      return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
    } catch (GeneralSecurityException | IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static byte[] getKeyBytes(String key, String keyPrefix, String keySuffix) {
    int startIndex = key.indexOf(keyPrefix);
    int endIndex = key.indexOf(keySuffix);

    String base64 = key.substring(startIndex + keyPrefix.length(), endIndex).replaceAll("\\s", "");
    return Base64.getDecoder().decode(base64);
  }

  private static KeySpec getPublicKeySpec(String publicKey) throws IOException, GeneralSecurityException {
    byte[] bytes = getKeyBytes(publicKey, PKCS_1_PUBLIC_KEY_START, PKCS_1_PUBLIC_KEY_END);
    DerInputStream derReader = new DerInputStream(bytes);
    DerValue[] seq = derReader.getSequence(0);

    if (seq.length != 2) {
      throw new GeneralSecurityException("Could not parse a PKCS1 private key.");
    }

    BigInteger modulus = seq[0].getBigInteger();
    BigInteger publicExponent = seq[1].getBigInteger();

    return new RSAPublicKeySpec(modulus, publicExponent);
  }

  private static KeySpec getRSAPrivateKeySpec(String privateKey) throws IOException, GeneralSecurityException {
    byte[] bytes = getKeyBytes(privateKey, PKCS_1_PRIVATE_KEY_START, PKCS_1_PRIVATE_KEY_END);
    DerInputStream derReader = new DerInputStream(bytes);
    DerValue[] seq = derReader.getSequence(0);

    if (seq.length < 9) {
      throw new GeneralSecurityException("Could not parse a PKCS1 private key.");
    }

    // skip version seq[0];
    BigInteger modulus = seq[1].getBigInteger();
    BigInteger publicExponent = seq[2].getBigInteger();
    BigInteger privateExponent = seq[3].getBigInteger();
    BigInteger primeP = seq[4].getBigInteger();
    BigInteger primeQ = seq[5].getBigInteger();
    BigInteger primeExponentP = seq[6].getBigInteger();
    BigInteger primeExponentQ = seq[7].getBigInteger();
    BigInteger crtCoefficient = seq[8].getBigInteger();
    return new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient);
  }
}
