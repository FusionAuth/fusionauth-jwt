/*
 * Copyright (c) 2016-2017, Inversoft Inc., All Rights Reserved
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
import sun.security.x509.X509CertImpl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.primeframework.jwt.rsa.PEMUtils.PKCS_1_PRIVATE_KEY_PREFIX;
import static org.primeframework.jwt.rsa.PEMUtils.PKCS_1_PRIVATE_KEY_SUFFIX;
import static org.primeframework.jwt.rsa.PEMUtils.PKCS_1_PUBLIC_KEY_PREFIX;
import static org.primeframework.jwt.rsa.PEMUtils.PKCS_1_PUBLIC_KEY_SUFFIX;
import static org.primeframework.jwt.rsa.PEMUtils.PKCS_8_PRIVATE_KEY_PREFIX;
import static org.primeframework.jwt.rsa.PEMUtils.PKCS_8_PRIVATE_KEY_SUFFIX;
import static org.primeframework.jwt.rsa.PEMUtils.X509_CERTIFICATE_PREFIX;
import static org.primeframework.jwt.rsa.PEMUtils.X509_CERTIFICATE_SUFFIX;
import static org.primeframework.jwt.rsa.PEMUtils.X509_PUBLIC_KEY_PREFIX;
import static org.primeframework.jwt.rsa.PEMUtils.X509_PUBLIC_KEY_SUFFIX;

/**
 * RSA Key Helper.
 *
 * @author Daniel DeGroff
 */
public class RSAUtils {
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
   * Return the private key in a PEM formatted String.
   *
   * @param privateKey The private key.
   * @return a string in PEM format.
   */
  public static String getPEMFromPrivateKey(PrivateKey privateKey) {
    return getPEMFromKey(privateKey);
  }

  /**
   * Return the public key in a PEM formatted String.
   *
   * @param publicKey The publicKey key.
   * @return a string in PEM format.
   */
  public static String getPEMFromPublicKey(PublicKey publicKey) {
    return getPEMFromKey(publicKey);
  }

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
      return extractPublicKeyFromPEM(publicKey);
    } catch (GeneralSecurityException | IOException e) {
      throw new RuntimeException(e);
    }
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

  private static RSAPublicKey extractPublicKeyFromPEM(String publicKeyString) throws IOException, GeneralSecurityException {
    if (publicKeyString.contains(PKCS_1_PUBLIC_KEY_PREFIX)) {
      byte[] bytes = getKeyBytes(publicKeyString, PKCS_1_PUBLIC_KEY_PREFIX, PKCS_1_PUBLIC_KEY_SUFFIX);
      DerInputStream derReader = new DerInputStream(bytes);
      DerValue[] seq = derReader.getSequence(0);

      if (seq.length != 2) {
        throw new GeneralSecurityException("Could not parse a PKCS1 private key.");
      }

      BigInteger modulus = seq[0].getBigInteger();
      BigInteger publicExponent = seq[1].getBigInteger();
      return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
    } else if (publicKeyString.contains(X509_PUBLIC_KEY_PREFIX)) {
      byte[] bytes = getKeyBytes(publicKeyString, X509_PUBLIC_KEY_PREFIX, X509_PUBLIC_KEY_SUFFIX);
      return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
    } else if (publicKeyString.contains(X509_CERTIFICATE_PREFIX)) {
      byte[] bytes = getKeyBytes(publicKeyString, X509_CERTIFICATE_PREFIX, X509_CERTIFICATE_SUFFIX);
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      X509CertImpl certificate = (X509CertImpl) factory.generateCertificate(new ByteArrayInputStream(bytes));
      return (RSAPublicKey) certificate.getPublicKey();
    } else {
      throw new InvalidParameterException("Unexpected Public Key Format");
    }
  }

  private static byte[] getKeyBytes(String key, String keyPrefix, String keySuffix) {
    int startIndex = key.indexOf(keyPrefix);
    int endIndex = key.indexOf(keySuffix);

    String base64 = key.substring(startIndex + keyPrefix.length(), endIndex).replaceAll("\\s", "");
    return Base64.getDecoder().decode(base64);
  }

  private static String getPEMFromKey(Key key) {
    StringBuilder sb = new StringBuilder();
    if (key instanceof PrivateKey) {
      if (key.getFormat().equals("PKCS#1")) {
        sb.append(PKCS_1_PRIVATE_KEY_PREFIX).append("\n");
      } else if (key.getFormat().equals("PKCS#8")) {
        sb.append(PKCS_8_PRIVATE_KEY_PREFIX).append("\n");
      } else {
        throw new InvalidParameterException("Unexpected Private Key Format");
      }
    } else {
      sb.append(X509_PUBLIC_KEY_PREFIX).append("\n");
    }

    String encoded = new String(Base64.getEncoder().encode(key.getEncoded()));

    int index = 0;
    int lineLength = 65;
    while (index < encoded.length()) {
      sb.append(encoded.substring(index, Math.min(index + lineLength, encoded.length()))).append("\n");
      index += lineLength;
    }

    if (key instanceof PrivateKey) {
      if (key.getFormat().equals("PKCS#1")) {
        sb.append(PKCS_1_PRIVATE_KEY_SUFFIX).append("\n");
      } else if (key.getFormat().equals("PKCS#8")) {
        sb.append(PKCS_8_PRIVATE_KEY_SUFFIX).append("\n");
      }
    } else {
      sb.append(X509_PUBLIC_KEY_SUFFIX).append("\n");
    }

    return sb.toString();
  }

  private static KeySpec getRSAPrivateKeySpec(String privateKey) throws IOException, GeneralSecurityException {
    if (privateKey.contains(PKCS_1_PRIVATE_KEY_PREFIX)) {
      byte[] bytes = getKeyBytes(privateKey, PKCS_1_PRIVATE_KEY_PREFIX, PKCS_1_PRIVATE_KEY_SUFFIX);
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
    } else if (privateKey.contains(PKCS_8_PRIVATE_KEY_PREFIX)) {
      byte[] bytes = getKeyBytes(privateKey, PKCS_8_PRIVATE_KEY_PREFIX, PKCS_8_PRIVATE_KEY_SUFFIX);
      return new PKCS8EncodedKeySpec(bytes);
    } else {
      throw new InvalidParameterException("Unexpected Private Key Format");
    }
  }
}
