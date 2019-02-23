/*
 * Copyright (c) 2016-2019, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwt;

import io.fusionauth.jwt.domain.Header;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.domain.KeyPair;
import io.fusionauth.jwt.domain.KeyType;
import io.fusionauth.jwt.json.Mapper;
import io.fusionauth.pem.domain.PEM;

import java.nio.charset.Charset;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * Helper to generate new HMAC secrets, EC and RSA public / private key pairs and other fun things.
 *
 * @author Daniel DeGroff
 */
public class JWTUtils {
  /**
   * Convert a HEX <code>SHA-1</code> or <code>SHA-256</code> X.509 certificate fingerprint to an <code>x5t</code>
   * or <code>x5t#256</code> thumbprint respectively.
   *
   * @param fingerprint the SHA-1 or SHA-256 fingerprint
   * @return an x5t hash.
   */
  public static String convertFingerprintToThumbprint(String fingerprint) {
    byte[] bytes = HexUtils.toBytes(fingerprint);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /**
   * Convert an X.509 certificate thumbprint to a HEX <code>SHA-1</code> or <code>SHA-256</code> fingerprint respectively.
   * <p>
   * If a <code>x5t</code> thumbprint is provided, a SHA-1 HEX encoded fingerprint will be returned.
   * <p>
   * If a <code>x5t#256</code> thumbprint is provided, a SHA-256 HEX encoded fingerprint will be returned.
   *
   * @param x5tHash the x5t hash
   * @return a SHA-1 or SHA-256 fingerprint
   */
  public static String convertThumbprintToFingerprint(String x5tHash) {
    byte[] bytes = Base64.getUrlDecoder().decode(x5tHash.getBytes(Charset.forName("UTF-8")));
    return HexUtils.fromBytes(bytes);
  }

  /**
   * WARNING!! This is not a secure or safe way to decode a JWT, this will not perform any validation on the signature.
   * <p>
   * Consider the header returned from this method as un-trustworthy. This is intended for utility and a nice way to
   * read the JWT header, but do not use it in production to verify the integrity.
   *
   * @param encodedJWT the encoded JWT
   * @return a Header object
   */
  public static Header decodeHeader(String encodedJWT) {
    Objects.requireNonNull(encodedJWT);

    String[] parts = encodedJWT.split("\\.");
    if (parts.length == 3 || (parts.length == 2 && encodedJWT.endsWith("."))) {
      return Mapper.deserialize(Base64.getUrlDecoder().decode(parts[0]), Header.class);
    }

    throw new InvalidJWTException("The encoded JWT is not properly formatted. Expected a three part dot separated string.");
  }

  /**
   * WARNING!! This is not a secure or safe way to decode a JWT, this will not perform any validation on the signature.
   * <p>
   * Consider the JWT returned from this method as un-trustworthy. This is intended for utility and a nice way to
   * read the JWT, but do not use it in production to verify the claims contained in this JWT.
   *
   * @param encodedJWT the encoded JWT
   * @return a JWT object
   */
  public static JWT decodePayload(String encodedJWT) {
    Objects.requireNonNull(encodedJWT);

    String[] parts = encodedJWT.split("\\.");
    if (parts.length == 3 || (parts.length == 2 && encodedJWT.endsWith("."))) {
      return Mapper.deserialize(Base64.getUrlDecoder().decode(parts[1]), JWT.class);
    }

    throw new InvalidJWTException("The encoded JWT is not properly formatted. Expected a three part dot separated string.");
  }

  /**
   * Generate a new public / private key pair using a 2048 bit RSA key. This is the minimum key length for use with an
   * RSA signing scheme for JWT.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate2048_RSAKeyPair() {
    return generateKeyPair(2048, KeyType.RSA);
  }

  /**
   * Generate a new public / private key pair using a 256 bit EC key. A 256 bit EC key is roughly equivalent to a 3072 bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate256_ECKeyPair() {
    return generateKeyPair(256, KeyType.EC);
  }

  /**
   * Generate a new public / private key pair using a 3072 bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate3072_RSAKeyPair() {
    return generateKeyPair(3072, KeyType.RSA);
  }

  /**
   * Generate a new public / private key pair using a 384 bit EC key. A 384 bit EC key is roughly equivalent to a 7680 bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate384_ECKeyPair() {
    return generateKeyPair(384, KeyType.EC);
  }

  /**
   * Generate a new public / private key pair using a 4096 bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate4096_RSAKeyPair() {
    return generateKeyPair(4096, KeyType.RSA);
  }

  /**
   * Generate a new public / private key pair using a 521 bit EC key. A 521 bit EC key is roughly equivalent to a 15,360 bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate521_ECKeyPair() {
    return generateKeyPair(521, KeyType.EC);
  }

  /**
   * Generate the <code>x5t</code> - the X.509 certificate thumbprint to be used in JWT header.
   *
   * @param algorithm          the algorithm used to calculate the hash, generally SHA-1 or SHA-256.
   * @param encodedCertificate the Base64 encoded certificate
   * @return an x5t hash.
   */
  public static String generateJWS_x5t(String algorithm, String encodedCertificate) {
    byte[] bytes = Base64.getDecoder().decode(encodedCertificate.getBytes(Charset.forName("UTF-8")));
    return digest(algorithm, bytes);
  }

  /**
   * Generate the <code>x5t</code> - the X.509 certificate thumbprint to be used in JWT header.
   *
   * @param encodedCertificate the Base64 encoded certificate
   * @return an x5t hash.
   */
  public static String generateJWS_x5t(String encodedCertificate) {
    return generateJWS_x5t("SHA-1", encodedCertificate);
  }

  /**
   * Generate the <code>x5t</code> - the X.509 certificate thumbprint to be used in JWT header.
   *
   * @param algorithm             the algorithm used to calculate the hash, generally SHA-1 or SHA-256.
   * @param derEncodedCertificate the DER encoded certificate
   * @return an x5t hash.
   */
  public static String generateJWS_x5t(String algorithm, byte[] derEncodedCertificate) {
    return digest(algorithm, derEncodedCertificate);
  }

  /**
   * Generate the <code>x5t</code> - the X.509 certificate thumbprint to be used in JWT header.
   *
   * @param derEncodedCertificate the DER encoded certificate
   * @return an x5t hash.
   */
  public static String generateJWS_x5t(byte[] derEncodedCertificate) {
    return digest("SHA-1", derEncodedCertificate);
  }

  /**
   * Generate a 32 byte (256 bit) HMAC secret for use with a SHA-256 hash.
   *
   * @return a secret for use with an HMAC signing and verification scheme.
   */
  public static String generateSHA256_HMACSecret() {
    byte[] buffer = new byte[32];
    new SecureRandom().nextBytes(buffer);
    return Base64.getEncoder().encodeToString(buffer);
  }

  /**
   * Generate a 48 byte (384 bit) HMAC secret for use with a SHA-384 hash.
   *
   * @return a secret for use with an HMAC signing and verification scheme.
   */
  public static String generateSHA384_HMACSecret() {
    byte[] buffer = new byte[48];
    new SecureRandom().nextBytes(buffer);
    return Base64.getEncoder().encodeToString(buffer);
  }

  /**
   * Generate a 64 byte (512 bit) HMAC secret for use with a SHA-512 hash.
   *
   * @return a secret for use with an HMAC signing and verification scheme.
   */
  public static String generateSHA512_HMACSecret() {
    byte[] buffer = new byte[64];
    new SecureRandom().nextBytes(buffer);
    return Base64.getEncoder().encodeToString(buffer);
  }

  private static String digest(String algorithm, byte[] bytes) {
    MessageDigest messageDigest;
    try {
      messageDigest = MessageDigest.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalArgumentException("No such algorithm [" + algorithm + "]");
    }

    byte[] digest = messageDigest.digest(bytes);
    return new String(Base64.getUrlEncoder().withoutPadding().encode(digest));
  }

  /**
   * Generate a new Public / Private key pair with a key size of the provided length.
   *
   * @param keySize the length of the key in bits
   * @return a public and private key in PEM format.
   */
  private static KeyPair generateKeyPair(int keySize, KeyType keyType) {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyType.name());
      keyPairGenerator.initialize(keySize);
      java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

      String privateKey = PEM.encode(keyPair.getPrivate(), keyPair.getPublic());
      String publicKey = PEM.encode(keyPair.getPublic());
      return new KeyPair(privateKey, publicKey);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
