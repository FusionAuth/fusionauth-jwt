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

package io.fusionauth.jwt.ec;

import io.fusionauth.jwt.InvalidKeyTypeException;
import io.fusionauth.jwt.JWTSigningException;
import io.fusionauth.jwt.MissingPrivateKeyException;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.pem.domain.PEM;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.util.Objects;

/**
 * @author Daniel DeGroff
 */
public class ECSigner implements Signer {
  private final Algorithm algorithm;

  private final String kid;

  private final ECPrivateKey privateKey;

  private ECSigner(Algorithm algorithm, String privateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(privateKey);

    this.algorithm = algorithm;
    this.kid = kid;
    PEM pem = PEM.decode(privateKey);
    if (pem.privateKey == null) {
      throw new MissingPrivateKeyException("The provided PEM encoded string did not contain a private key.");
    }

    if (!(pem.privateKey instanceof ECPrivateKey)) {
      throw new InvalidKeyTypeException("Expecting an EC private key, but found " + pem.privateKey.getAlgorithm() + " / " + pem.privateKey.getFormat() + "");
    }
    this.privateKey = pem.getPrivateKey();
  }

  /**
   * Build a new EC signer using a SHA-256 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @param kid        The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new EC signer.
   */
  public static ECSigner newSHA256Signer(String privateKey, String kid) {
    return new ECSigner(Algorithm.ES256, privateKey, kid);
  }

  /**
   * Build a new EC signer using a SHA-256 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @return a new EC signer.
   */
  public static ECSigner newSHA256Signer(String privateKey) {
    return new ECSigner(Algorithm.ES256, privateKey, null);
  }

  /**
   * Build a new EC signer using a SHA-384 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @param kid        The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new EC signer.
   */
  public static ECSigner newSHA384Signer(String privateKey, String kid) {
    return new ECSigner(Algorithm.ES384, privateKey, kid);
  }

  /**
   * Build a new EC signer using a SHA-384 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @return a new EC signer.
   */
  public static ECSigner newSHA384Signer(String privateKey) {
    return new ECSigner(Algorithm.ES384, privateKey, null);
  }

  /**
   * Build a new EC signer using a SHA-512 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @param kid        The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new EC signer.
   */
  public static ECSigner newSHA512Signer(String privateKey, String kid) {
    return new ECSigner(Algorithm.ES512, privateKey, kid);
  }

  /**
   * Build a new EC signer using a SHA-512 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @return a new EC signer.
   */
  public static ECSigner newSHA512Signer(String privateKey) {
    return new ECSigner(Algorithm.ES512, privateKey, null);
  }

  @Override
  public Algorithm getAlgorithm() {
    return algorithm;
  }

  @Override
  public String getKid() {
    return kid;
  }

  @Override
  public byte[] sign(String message) {
    Objects.requireNonNull(message);

    try {
      Signature signature = Signature.getInstance(algorithm.getName());
      signature.initSign(privateKey, new SecureRandom());
      signature.update((message).getBytes(StandardCharsets.UTF_8));
      byte[] derEncoded = signature.sign();

      return new ECDSASignature(derEncoded).derDecode(algorithm);
    } catch (InvalidKeyException | IOException | NoSuchAlgorithmException | SignatureException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
