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

import org.primeframework.jwt.Signer;
import org.primeframework.jwt.domain.Algorithm;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Objects;

/**
 * This class can sign a JWT using an RSA Private key.
 *
 * @author Daniel DeGroff
 */
public class RSASigner implements Signer {

  private final Algorithm algorithm;

  private PrivateKey privateKey;

  private RSASigner(Algorithm algorithm, String privateKey) {
    this.algorithm = algorithm;
    this.privateKey = RSAUtils.getPrivateKeyFromPEM(privateKey);
  }

  public static RSASigner newRSA256Signer(String privateKey) {
    return new RSASigner(Algorithm.RS256, privateKey);
  }

  public static RSASigner newRSA512Signer(String privateKey) {
    return new RSASigner(Algorithm.RS512, privateKey);
  }

  @Override
  public Algorithm getAlgorithm() {
    return algorithm;
  }

  public byte[] sign(String message) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(privateKey);

    try {
      Signature signature = Signature.getInstance(algorithm.getName());
      signature.initSign(privateKey);
      signature.update(message.getBytes());
      return signature.sign();
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      throw new RuntimeException(e);
    }
  }
}
