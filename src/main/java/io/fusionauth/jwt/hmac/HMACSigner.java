/*
 * Copyright (c) 2016-2023, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwt.hmac;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

import io.fusionauth.jwt.JWTSigningException;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.security.CryptoProvider;
import io.fusionauth.security.DefaultCryptoProvider;

/**
 * This class can sign and verify a JWT that was signed using HMAC.
 *
 * @author Daniel DeGroff
 */
public class HMACSigner implements Signer {
  private final Algorithm algorithm;

  private final CryptoProvider cryptoProvider;

  private final String kid;

  private final byte[] secret;

  private HMACSigner(Algorithm algorithm, byte[] secret, String kid, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(cryptoProvider);
    Objects.requireNonNull(secret);

    this.algorithm = algorithm;
    this.cryptoProvider = cryptoProvider;
    this.kid = kid;
    this.secret = secret;
  }

  private HMACSigner(Algorithm algorithm, String secret, String kid, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(cryptoProvider);
    Objects.requireNonNull(secret);

    this.algorithm = algorithm;
    this.cryptoProvider = cryptoProvider;
    this.kid = kid;
    this.secret = secret.getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Build a new HMAC signer using a SHA-256 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA256Signer(byte[] secret) {
    return newSHA256Signer(secret, null, new DefaultCryptoProvider());
  }

  /**
   * Build a new HMAC signer using a SHA-256 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA256Signer(String secret) {
    return newSHA256Signer(secret, null, new DefaultCryptoProvider());
  }

  /**
   * Build a new HMAC signer using a SHA-256 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @param kid    The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA256Signer(byte[] secret, String kid) {
    return newSHA256Signer(secret, kid, new DefaultCryptoProvider());
  }

  /**
   * Build a new HMAC signer using a SHA-256 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @param kid    The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA256Signer(String secret, String kid) {
    return newSHA256Signer(secret, kid, new DefaultCryptoProvider());
  }

  /**
   * Build a new HMAC signer using a SHA-256 hash.
   *
   * @param secret         The secret used to generate the HMAC hash.
   * @param cryptoProvider The crypto provider used to get the MAC digest algorithm.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA256Signer(String secret, CryptoProvider cryptoProvider) {
    return newSHA256Signer(secret, null, cryptoProvider);
  }

  /**
   * Build a new HMAC signer using a SHA-256 hash.
   *
   * @param secret         The secret used to generate the HMAC hash.
   * @param kid            The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @param cryptoProvider The crypto provider used to get the MAC digest algorithm.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA256Signer(byte[] secret, String kid, CryptoProvider cryptoProvider) {
    return new HMACSigner(HMAC.HS256, secret, kid, cryptoProvider);
  }

  /**
   * Build a new HMAC signer using a SHA-256 hash.
   *
   * @param secret         The secret used to generate the HMAC hash.
   * @param kid            The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @param cryptoProvider The crypto provider used to get the MAC digest algorithm.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA256Signer(String secret, String kid, CryptoProvider cryptoProvider) {
    return new HMACSigner(HMAC.HS256, secret, kid, cryptoProvider);
  }

  /**
   * Build a new HMAC signer using a SHA-384 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA384Signer(byte[] secret) {
    return newSHA384Signer(secret, null, new DefaultCryptoProvider());
  }

  /**
   * Build a new HMAC signer using a SHA-384 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA384Signer(String secret) {
    return newSHA384Signer(secret, null, new DefaultCryptoProvider());
  }

  /**
   * Build a new HMAC signer using a SHA-384 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @param kid    The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA384Signer(byte[] secret, String kid) {
    return newSHA384Signer(secret, kid, new DefaultCryptoProvider());
  }

  /**
   * Build a new HMAC signer using a SHA-384 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @param kid    The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA384Signer(String secret, String kid) {
    return newSHA384Signer(secret, kid, new DefaultCryptoProvider());
  }

  /**
   * Build a new HMAC signer using a SHA-384 hash.
   *
   * @param secret         The secret used to generate the HMAC hash.
   * @param cryptoProvider The crypto provider used to get the MAC digest algorithm.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA384Signer(String secret, CryptoProvider cryptoProvider) {
    return newSHA384Signer(secret, null, cryptoProvider);
  }

  /**
   * Build a new HMAC signer using a SHA-384 hash.
   *
   * @param secret         The secret used to generate the HMAC hash.
   * @param kid            The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @param cryptoProvider The crypto provider used to get the MAC digest algorithm.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA384Signer(byte[] secret, String kid, CryptoProvider cryptoProvider) {
    return new HMACSigner(HMAC.HS384, secret, kid, cryptoProvider);
  }

  /**
   * Build a new HMAC signer using a SHA-384 hash.
   *
   * @param secret         The secret used to generate the HMAC hash.
   * @param kid            The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @param cryptoProvider The crypto provider used to get the MAC digest algorithm.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA384Signer(String secret, String kid, CryptoProvider cryptoProvider) {
    return new HMACSigner(HMAC.HS384, secret, kid, cryptoProvider);
  }

  /**
   * Build a new HMAC signer using a SHA-512 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA512Signer(byte[] secret) {
    return newSHA512Signer(secret, null, new DefaultCryptoProvider());
  }

  /**
   * Build a new HMAC signer using a SHA-512 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA512Signer(String secret) {
    return newSHA512Signer(secret, null, new DefaultCryptoProvider());
  }

  /**
   * Build a new HMAC signer using a SHA-512 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @param kid    The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA512Signer(byte[] secret, String kid) {
    return newSHA512Signer(secret, kid, new DefaultCryptoProvider());
  }

  /**
   * Build a new HMAC signer using a SHA-512 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @param kid    The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA512Signer(String secret, String kid) {
    return newSHA512Signer(secret, kid, new DefaultCryptoProvider());
  }

  /**
   * Build a new HMAC signer using a SHA-512 hash.
   *
   * @param secret         The secret used to generate the HMAC hash.
   * @param cryptoProvider The crypto provider used to get the MAC digest algorithm.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA512Signer(String secret, CryptoProvider cryptoProvider) {
    return newSHA512Signer(secret, null, cryptoProvider);
  }

  /**
   * Build a new HMAC signer using a SHA-512 hash.
   *
   * @param secret         The secret used to generate the HMAC hash.
   * @param kid            The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @param cryptoProvider The crypto provider used to get the MAC digest algorithm.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA512Signer(byte[] secret, String kid, CryptoProvider cryptoProvider) {
    return new HMACSigner(HMAC.HS512, secret, kid, cryptoProvider);
  }

  /**
   * Build a new HMAC signer using a SHA-512 hash.
   *
   * @param secret         The secret used to generate the HMAC hash.
   * @param kid            The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @param cryptoProvider The crypto provider used to get the MAC digest algorithm.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA512Signer(String secret, String kid, CryptoProvider cryptoProvider) {
    return new HMACSigner(HMAC.HS512, secret, kid, cryptoProvider);
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
      Mac mac = cryptoProvider.getMacInstance(algorithm.value);
      mac.init(new SecretKeySpec(secret, algorithm.value));
      return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
