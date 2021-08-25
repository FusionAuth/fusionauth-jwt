/*
 * Copyright (c) 2018-2020, FusionAuth, All Rights Reserved
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
import io.fusionauth.security.CryptoProvider;
import io.fusionauth.security.DefaultCryptoProvider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
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

  private final CryptoProvider cryptoProvider;

  private ECSigner(Algorithm algorithm, PrivateKey privateKey, String kid, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(cryptoProvider);
    Objects.requireNonNull(privateKey);

    this.algorithm = algorithm;
    this.cryptoProvider = cryptoProvider;
    this.kid = kid;

    if (!(privateKey instanceof ECPrivateKey)) {
      throw new InvalidKeyTypeException("Expecting a private key of type [ECPrivateKey], but found [" + privateKey.getClass().getSimpleName() + "].");
    }

    this.privateKey = (ECPrivateKey) privateKey;
  }

  private ECSigner(Algorithm algorithm, String privateKey, String kid, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(cryptoProvider);
    Objects.requireNonNull(privateKey);

    this.algorithm = algorithm;
    this.cryptoProvider = cryptoProvider;
    this.kid = kid;
    PEM pem = PEM.decode(privateKey);
    if (pem.privateKey == null) {
      throw new MissingPrivateKeyException("The provided PEM encoded string did not contain a private key.");
    }

    if (!(pem.privateKey instanceof ECPrivateKey)) {
      throw new InvalidKeyTypeException("Expecting a private key of type [ECPrivateKey], but found [" + pem.privateKey.getClass().getSimpleName() + "].");
    }

    this.privateKey = pem.getPrivateKey();
  }

  /**
   * Build a new EC signer using a SHA-256 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @return a new EC signer.
   */
  public static ECSigner newSHA256Signer(String privateKey) {
    return new ECSigner(Algorithm.ES256, privateKey, null, new DefaultCryptoProvider());
  }

  /**
   * Build a new EC signer using a SHA-256 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @param kid        The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new EC signer.
   */
  public static ECSigner newSHA256Signer(String privateKey, String kid) {
    return new ECSigner(Algorithm.ES256, privateKey, kid, new DefaultCryptoProvider());
  }

  /**
   * Build a new EC signer using a SHA-256 hash.
   *
   * @param privateKey     The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @param cryptoProvider The crypto provider used to get the ECDSA Signature algorithm.
   * @return a new EC signer.
   */
  public static ECSigner newSHA256Signer(String privateKey, CryptoProvider cryptoProvider) {
    return new ECSigner(Algorithm.ES256, privateKey, null, cryptoProvider);
  }

  /**
   * Build a new EC signer using a SHA-256 hash.
   *
   * @param privateKey     The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @param kid            The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @param cryptoProvider The crypto provider used to get the ECDSA Signature Algorithm.
   * @return a new EC signer.
   */
  public static ECSigner newSHA256Signer(String privateKey, String kid, CryptoProvider cryptoProvider) {
    return new ECSigner(Algorithm.ES256, privateKey, kid, cryptoProvider);
  }

  /**
   * Build a new EC signer using a SHA-256 hash.
   *
   * @param privateKey The private key.
   * @return a new EC signer.
   */
  public static ECSigner newSHA256Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES256, privateKey, null, new DefaultCryptoProvider());
  }

  /**
   * Build a new EC signer using a SHA-256 hash.
   *
   * @param privateKey The private key.
   * @param kid        The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new EC signer.
   */
  public static ECSigner newSHA256Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES256, privateKey, kid, new DefaultCryptoProvider());
  }

  /**
   * Build a new EC signer using a SHA-256 hash.
   *
   * @param privateKey     The private key.
   * @param cryptoProvider The crypto provider used to get the ECDSA Signature algorithm.
   * @return a new EC signer.
   */
  public static ECSigner newSHA256Signer(PrivateKey privateKey, CryptoProvider cryptoProvider) {
    return new ECSigner(Algorithm.ES256, privateKey, null, cryptoProvider);
  }

  /**
   * Build a new EC signer using a SHA-256 hash.
   *
   * @param privateKey     The private key.
   * @param kid            The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @param cryptoProvider The crypto provider used to get the ECDSA Signature Algorithm.
   * @return a new EC signer.
   */
  public static ECSigner newSHA256Signer(PrivateKey privateKey, String kid, CryptoProvider cryptoProvider) {
    return new ECSigner(Algorithm.ES256, privateKey, kid, cryptoProvider);
  }

  /**
   * Build a new EC signer using a SHA-384 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @return a new EC signer.
   */
  public static ECSigner newSHA384Signer(String privateKey) {
    return new ECSigner(Algorithm.ES384, privateKey, null, new DefaultCryptoProvider());
  }

  /**
   * Build a new EC signer using a SHA-384 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @param kid        The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new EC signer.
   */
  public static ECSigner newSHA384Signer(String privateKey, String kid) {
    return new ECSigner(Algorithm.ES384, privateKey, kid, new DefaultCryptoProvider());
  }

  /**
   * Build a new EC signer using a SHA-384 hash.
   *
   * @param privateKey     The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @param cryptoProvider The crypto provider used to get the ECDSA Signature algorithm.
   * @return a new EC signer.
   */
  public static ECSigner newSHA384Signer(String privateKey, CryptoProvider cryptoProvider) {
    return new ECSigner(Algorithm.ES384, privateKey, null, cryptoProvider);
  }

  /**
   * Build a new EC signer using a SHA-384 hash.
   *
   * @param privateKey     The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @param kid            The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @param cryptoProvider The crypto provider used to get the ECDSA Signature algorithm.
   * @return a new EC signer.
   */
  public static ECSigner newSHA384Signer(String privateKey, String kid, CryptoProvider cryptoProvider) {
    return new ECSigner(Algorithm.ES384, privateKey, kid, cryptoProvider);
  }

  /**
   * Build a new EC signer using a SHA-384 hash.
   *
   * @param privateKey The private key.
   * @return a new EC signer.
   */
  public static ECSigner newSHA384Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES384, privateKey, null, new DefaultCryptoProvider());
  }

  /**
   * Build a new EC signer using a SHA-384 hash.
   *
   * @param privateKey The private key.
   * @param kid        The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new EC signer.
   */
  public static ECSigner newSHA384Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES384, privateKey, kid, new DefaultCryptoProvider());
  }

  /**
   * Build a new EC signer using a SHA-384 hash.
   *
   * @param privateKey     The private key.
   * @param cryptoProvider The crypto provider used to get the ECDSA Signature algorithm.
   * @return a new EC signer.
   */
  public static ECSigner newSHA384Signer(PrivateKey privateKey, CryptoProvider cryptoProvider) {
    return new ECSigner(Algorithm.ES384, privateKey, null, cryptoProvider);
  }

  /**
   * Build a new EC signer using a SHA-384 hash.
   *
   * @param privateKey     The private key.
   * @param kid            The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @param cryptoProvider The crypto provider used to get the ECDSA Signature algorithm.
   * @return a new EC signer.
   */
  public static ECSigner newSHA384Signer(PrivateKey privateKey, String kid, CryptoProvider cryptoProvider) {
    return new ECSigner(Algorithm.ES384, privateKey, kid, cryptoProvider);
  }

  /**
   * Build a new EC signer using a SHA-512 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @return a new EC signer.
   */
  public static ECSigner newSHA512Signer(String privateKey) {
    return new ECSigner(Algorithm.ES512, privateKey, null, new DefaultCryptoProvider());
  }

  /**
   * Build a new EC signer using a SHA-512 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @param kid        The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new EC signer.
   */
  public static ECSigner newSHA512Signer(String privateKey, String kid) {
    return new ECSigner(Algorithm.ES512, privateKey, kid, new DefaultCryptoProvider());
  }

  /**
   * Build a new EC signer using a SHA-512 hash.
   *
   * @param privateKey     The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @param cryptoProvider The crypto provider used to get the ECDSA Signature algorithm.
   * @return a new EC signer.
   */
  public static ECSigner newSHA512Signer(String privateKey, CryptoProvider cryptoProvider) {
    return new ECSigner(Algorithm.ES512, privateKey, null, cryptoProvider);
  }

  /**
   * Build a new EC signer using a SHA-512 hash.
   *
   * @param privateKey     The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @param kid            The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @param cryptoProvider The crypto provider used to get the ECDSA Signature algorithm.
   * @return a new EC signer.
   */
  public static ECSigner newSHA512Signer(String privateKey, String kid, CryptoProvider cryptoProvider) {
    return new ECSigner(Algorithm.ES512, privateKey, kid, cryptoProvider);
  }

  /**
   * Build a new EC signer using a SHA-512 hash.
   *
   * @param privateKey The private key.
   * @return a new EC signer.
   */
  public static ECSigner newSHA512Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES512, privateKey, null, new DefaultCryptoProvider());
  }

  /**
   * Build a new EC signer using a SHA-512 hash.
   *
   * @param privateKey The private key.
   * @param kid        The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new EC signer.
   */
  public static ECSigner newSHA512Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES512, privateKey, kid, new DefaultCryptoProvider());
  }

  /**
   * Build a new EC signer using a SHA-512 hash.
   *
   * @param privateKey     The private key.
   * @param cryptoProvider The crypto provider used to get the ECDSA Signature algorithm.
   * @return a new EC signer.
   */
  public static ECSigner newSHA512Signer(PrivateKey privateKey, CryptoProvider cryptoProvider) {
    return new ECSigner(Algorithm.ES512, privateKey, null, cryptoProvider);
  }

  /**
   * Build a new EC signer using a SHA-512 hash.
   *
   * @param privateKey     The private key.
   * @param kid            The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @param cryptoProvider The crypto provider used to get the ECDSA Signature algorithm.
   * @return a new EC signer.
   */
  public static ECSigner newSHA512Signer(PrivateKey privateKey, String kid, CryptoProvider cryptoProvider) {
    return new ECSigner(Algorithm.ES512, privateKey, kid, cryptoProvider);
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
      // In later versions of the JDK you can request a non DER encoded signature so we don't have to re-encode it.
      // - We could revisit this in the future if we want to depend on a later version of Java.
      //   To request the version we want, you can append "inP1363Format" to the algorithm name.
      //   Example : ES256inP1363Format instead of ES256.
      Signature signature = cryptoProvider.getSignatureInstance(algorithm.getName());
      signature.initSign(privateKey);
      signature.update((message).getBytes(StandardCharsets.UTF_8));
      byte[] derEncoded = signature.sign();

      return new ECDSASignature(derEncoded).derDecode(algorithm);
    } catch (InvalidKeyException | IOException | NoSuchAlgorithmException | SignatureException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
