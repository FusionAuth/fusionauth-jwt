/*
 * Copyright (c) 2017-2018, Inversoft Inc., All Rights Reserved
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

import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;

/**
 * @author Daniel DeGroff
 */
public class PEMUtils {
  // PEM Encoded RSA Private Key file (PKCS#1)  Start Tag
  public static final String PKCS_1_PRIVATE_KEY_PREFIX = "-----BEGIN RSA PRIVATE KEY-----";

  // PEM Encoded RSA Private Key file (PKCS#1) End Tag
  public static final String PKCS_1_PRIVATE_KEY_SUFFIX = "-----END RSA PRIVATE KEY-----";

  // RSA Public Key file (PKCS#1)  Start Tag
  public static final String PKCS_1_PUBLIC_KEY_PREFIX = "-----BEGIN RSA PUBLIC KEY-----";

  // RSA Public Key file (PKCS#1)  End Tag
  public static final String PKCS_1_PUBLIC_KEY_SUFFIX = "-----END RSA PUBLIC KEY-----";

  // PEM Encoded RSA Private Key file (PKCS#8)  Start Tag
  public static final String PKCS_8_PRIVATE_KEY_PREFIX = "-----BEGIN PRIVATE KEY-----";

  // PEM Encoded RSA Private Key file (PKCS#8)  End Tag
  public static final String PKCS_8_PRIVATE_KEY_SUFFIX = "-----END PRIVATE KEY-----";

  // PEM Encoded X.509 Certificate  Start Tag
  public static final String X509_CERTIFICATE_PREFIX = "-----BEGIN CERTIFICATE-----";

  // PEM Encoded X.509 Certificate End Tag
  public static final String X509_CERTIFICATE_SUFFIX = "-----END CERTIFICATE-----";

  // PEM Encoded RSA Public Key file (X.509)  Start Tag
  public static final String X509_PUBLIC_KEY_PREFIX = "-----BEGIN PUBLIC KEY-----";

  // PEM Encoded RSA Public Key file (X.509)  End Tag
  public static final String X509_PUBLIC_KEY_SUFFIX = "-----END PUBLIC KEY-----";

  private static final Base64.Encoder PEM_ENCODER = Base64.getMimeEncoder(64, new byte[]{'\n'});

  /**
   * Decode a PEM encoded certificate, returning only the Base64 encoded string.
   *
   * @param pemEncodedString the PEM encoded string version of the certificate.
   * @return a base64 encoded version of the certificate.
   */
  public static String decodeCertificate(String pemEncodedString) {
    int startIndex = pemEncodedString.indexOf(X509_CERTIFICATE_PREFIX);
    int endIndex = pemEncodedString.indexOf(X509_CERTIFICATE_SUFFIX);

    if (startIndex == -1 || endIndex == -1) {
      throw new InvalidParameterException("Unexpected Certificate Format");
    }

    return pemEncodedString.substring(startIndex + X509_CERTIFICATE_PREFIX.length(), endIndex).replaceAll("\\s", "");
  }

  /**
   * PEM encode a Base64 encoded string version of a certificate.
   *
   * @param encodedCertificate the Base64 encoded certificate
   * @return a PEM encoded certificate.
   */
  public static String encodeCertificate(String encodedCertificate) {
    StringBuilder sb = new StringBuilder(X509_CERTIFICATE_PREFIX).append("\n");
    int index = 0;
    while (index < encodedCertificate.length()) {
      sb.append(encodedCertificate.substring(index, Math.min(index + 64, encodedCertificate.length()))).append("\n");
      index = index + 64;
    }

    return sb.append(X509_CERTIFICATE_SUFFIX).toString();
  }

  /**
   * Return a PEM encoded string representation of the provided {@link PrivateKey}.
   *
   * @param privateKey the private key to PEM encode.
   * @return a PEM encoded key.
   */
  public static String encodePrivateKey(PrivateKey privateKey) {
    Objects.requireNonNull(privateKey);
    if (!privateKey.getAlgorithm().equals("RSA")) {
      throw new IllegalStateException("Only RSA keys are currently supported.");
    }

    if (privateKey.getFormat().equals("PKCS#8")) {
      return PKCS_8_PRIVATE_KEY_PREFIX + "\n" +
          PEM_ENCODER.encodeToString(privateKey.getEncoded()) + "\n" +
          PKCS_8_PRIVATE_KEY_SUFFIX;
    }

    throw new IllegalStateException("Only RSA PKCS#8 keys are currently supported. Provided key format [" + privateKey.getFormat() + "]");
  }

  /**
   * Return a PEM encoded string representation of the provided {@link PublicKey}.
   *
   * @param publicKey the public key to PEM encode
   * @return a PEM encoded key.
   */
  public static String encodePublicKey(PublicKey publicKey) {
    Objects.requireNonNull(publicKey);
    if (!publicKey.getAlgorithm().equals("RSA")) {
      throw new IllegalStateException("Only RSA keys are currently supported.");
    }

    if (publicKey.getFormat().equals("X.509")) {
      return X509_PUBLIC_KEY_PREFIX + "\n" +
          PEM_ENCODER.encodeToString(publicKey.getEncoded()) + "\n" +
          X509_PUBLIC_KEY_SUFFIX;
    }

    throw new IllegalStateException("Only RSA PKCS#8 keys are currently supported. Provided key format [" + publicKey.getFormat() + "]");
  }
}
