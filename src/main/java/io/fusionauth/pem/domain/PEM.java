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

package io.fusionauth.pem.domain;

import io.fusionauth.jwt.domain.Buildable;
import io.fusionauth.pem.PEMDecoder;
import io.fusionauth.pem.PEMEncoder;

import java.nio.file.Path;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Objects;

/**
 * @author Daniel DeGroff
 */
public class PEM implements Buildable<PEM> {
  // PEM Encoded EC Private key End Tag
  public static final String EC_PRIVATE_KEY_PREFIX = "-----BEGIN EC PRIVATE KEY-----";

  // PEM Encoded EC Private key Start Tag
  public static final String EC_PRIVATE_KEY_SUFFIX = "-----END EC PRIVATE KEY-----";

  // PEM Encoded RSA Private Key (PKCS#1) Start Tag
  public static final String PKCS_1_PRIVATE_KEY_PREFIX = "-----BEGIN RSA PRIVATE KEY-----";

  // PEM Encoded RSA Private Key file (PKCS#1) End Tag
  public static final String PKCS_1_PRIVATE_KEY_SUFFIX = "-----END RSA PRIVATE KEY-----";

  // RSA Public Key file (PKCS#1) Start Tag
  public static final String PKCS_1_PUBLIC_KEY_PREFIX = "-----BEGIN RSA PUBLIC KEY-----";

  // RSA Public Key file (PKCS#1) End Tag
  public static final String PKCS_1_PUBLIC_KEY_SUFFIX = "-----END RSA PUBLIC KEY-----";

  // PEM Encoded Private Key (PKCS#8) Start Tag
  public static final String PKCS_8_PRIVATE_KEY_PREFIX = "-----BEGIN PRIVATE KEY-----";

  // PEM Encoded Private Key (PKCS#8) End Tag
  public static final String PKCS_8_PRIVATE_KEY_SUFFIX = "-----END PRIVATE KEY-----";

  // PEM Encoded X.509 Certificate Start Tag
  public static final String X509_CERTIFICATE_PREFIX = "-----BEGIN CERTIFICATE-----";

  // PEM Encoded X.509 Certificate End Tag
  public static final String X509_CERTIFICATE_SUFFIX = "-----END CERTIFICATE-----";

  // PEM Encoded Public Key (X.509) Start Tag
  public static final String X509_PUBLIC_KEY_PREFIX = "-----BEGIN PUBLIC KEY-----";

  // PEM Encoded Public Key (X.509) End Tag
  public static final String X509_PUBLIC_KEY_SUFFIX = "-----END PUBLIC KEY-----";

  public Certificate certificate;

  public PrivateKey privateKey;

  public PublicKey publicKey;

  public PEM(PrivateKey privateKey, PublicKey publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  public PEM(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  public PEM(Certificate certificate) {
    this.certificate = certificate;
    this.publicKey = certificate.getPublicKey();
  }

  public PEM(PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  /**
   * Decode a PEM in string format.
   *
   * @param path a path to an encoded PEM
   * @return a PEM object
   */
  public static PEM decode(Path path) {
    return new PEMDecoder().decode(path);
  }

  /**
   * Decode a PEM in string format.
   *
   * @param encodedPEM an encoded PEM
   * @return a PEM object
   */
  public static PEM decode(String encodedPEM) {
    return new PEMDecoder().decode(encodedPEM);
  }

  /**
   * Decode a PEM in string format.
   *
   * @param bytes a byte array of the PEM
   * @return a PEM object
   */
  public static PEM decode(byte[] bytes) {
    return new PEMDecoder().decode(bytes);
  }

  /**
   * Encode a key in PEM format.
   *
   * @param key a key
   * @return an encoded PEM
   */
  public static String encode(Key key) {
    return new PEMEncoder().encode(key);
  }

  /**
   * Encode a private key in PEM format given both the private and public key.
   * <p>
   * The use of this method is only necessary if you are providing a private key that does not contain the encoded public key.
   *
   * @param privateKey a private key
   * @param publicKey  a public key
   * @return an encoded PEM
   */
  public static String encode(PrivateKey privateKey, PublicKey publicKey) {
    return new PEMEncoder().encode(privateKey, publicKey);
  }

  /**
   * Encode a certificate in PEM format.
   *
   * @param certificate The certificate.
   * @return An encoded PEM.
   */
  public static String encode(Certificate certificate) {
    return new PEMEncoder().encode(certificate);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof PEM)) return false;
    PEM pem = (PEM) o;
    return Objects.equals(certificate, pem.certificate) &&
        Objects.equals(privateKey, pem.privateKey) &&
        Objects.equals(publicKey, pem.publicKey);
  }

  public Certificate getCertificate() {
    return certificate;
  }

  public <T extends PrivateKey> T getPrivateKey() {
    //noinspection unchecked
    return (T) privateKey;
  }

  public <T extends PublicKey> T getPublicKey() {
    //noinspection unchecked
    return (T) publicKey;
  }

  @Override
  public int hashCode() {
    return Objects.hash(certificate, privateKey, publicKey);
  }
}
