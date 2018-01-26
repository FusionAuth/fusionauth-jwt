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

package org.primeframework.jwt.rsa;

import org.primeframework.jwt.Signer;
import org.primeframework.jwt.domain.Algorithm;
import org.primeframework.jwt.domain.InvalidKeyLengthException;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Objects;

/**
 * This class can sign a JWT using an RSA Private key.
 *
 * @author Daniel DeGroff
 */
public class RSASigner implements Signer {

  private final Algorithm algorithm;

  private RSAPrivateKey privateKey;

  private RSASigner(Algorithm algorithm, String privateKey) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(privateKey);
    this.algorithm = algorithm;
    this.privateKey = RSAUtils.getPrivateKeyFromPEM(privateKey);

    int keyLength = this.privateKey.getModulus().bitLength();
    if (keyLength < 2048) {
      throw new InvalidKeyLengthException("Key length of [" + keyLength + "] is less than the required key length of 2048 bits.");
    }
  }

  /**
   * Build a new RSA signer using a SHA-256 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @return a new RSA signer.
   */
  public static RSASigner newSHA256Signer(String privateKey) {
    return new RSASigner(Algorithm.RS256, privateKey);
  }

  /**
   * Build a new RSA signer using a SHA-384 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @return a new RSA signer.
   */
  public static RSASigner newSHA384Signer(String privateKey) {
    return new RSASigner(Algorithm.RS384, privateKey);
  }

  /**
   * Build a new RSA signer using a SHA-512 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @return a new RSA signer.
   */
  public static RSASigner newSHA512Signer(String privateKey) {
    return new RSASigner(Algorithm.RS512, privateKey);
  }

  @Override
  public Algorithm getAlgorithm() {
    return algorithm;
  }

  public byte[] sign(String message) {
    try {
      Signature signature = Signature.getInstance(algorithm.getName());
      signature.initSign(privateKey);
      signature.update(message.getBytes(StandardCharsets.UTF_8));
      return signature.sign();
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      throw new RuntimeException(e);
    }
  }
}
