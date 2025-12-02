/*
 * Copyright (c) 2018-2025, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwks;

import io.fusionauth.der.DerDecodingException;
import io.fusionauth.der.DerInputStream;
import io.fusionauth.der.ObjectIdentifier;
import io.fusionauth.jwks.domain.JSONWebKey;
import io.fusionauth.jwt.JWTUtils;
import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.jwt.domain.KeyType;
import io.fusionauth.pem.domain.PEM;
import io.fusionauth.security.KeyUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Collections;
import java.util.Objects;

import static io.fusionauth.jwks.JWKUtils.base64EncodeUint;

/**
 * @author Daniel DeGroff
 */
public class JSONWebKeyBuilder {
  /**
   * Build a JSON Web Key from the provided encoded PEM.
   *
   * @param encodedPEM the encoded PEM in string format
   * @return a JSON Web Key
   */
  public JSONWebKey build(String encodedPEM) {
    Objects.requireNonNull(encodedPEM);
    PEM pem = PEM.decode(encodedPEM);
    if (pem.privateKey != null) {
      return build(pem.privateKey);
    } else if (pem.certificate != null) {
      // Prefer the certificate if available
      return build(pem.certificate);
    } else if (pem.publicKey != null) {
      return build(pem.publicKey);
    }

    throw new JSONWebKeyBuilderException("The provided PEM did not contain a public or private key.");
  }

  /**
   * Build a JSON Web Key from the provided PrivateKey.
   *
   * @param privateKey the private key
   * @return a JSON Web Key
   */
  public JSONWebKey build(PrivateKey privateKey) {
    Objects.requireNonNull(privateKey);
    JSONWebKey key = new JSONWebKey();

    key.kty = getKeyType(privateKey);
    key.use = "sig";
    if (privateKey instanceof RSAPrivateKey rsaPrivateKey) {
      key.n = base64EncodeUint(rsaPrivateKey.getModulus());
      key.d = base64EncodeUint(rsaPrivateKey.getPrivateExponent());
    }

    // If this is a CRT (Chinese Remainder Theorem) private key, collect additional information
    if (privateKey instanceof RSAPrivateCrtKey rsaPrivateKey) {
      key.e = base64EncodeUint(rsaPrivateKey.getPublicExponent());
      key.p = base64EncodeUint(rsaPrivateKey.getPrimeP());
      key.q = base64EncodeUint(rsaPrivateKey.getPrimeQ());
      key.qi = base64EncodeUint(rsaPrivateKey.getCrtCoefficient());

      // d mod (p-1)
      BigInteger dp = rsaPrivateKey.getPrivateExponent().mod(rsaPrivateKey.getPrimeP().subtract(BigInteger.valueOf(1)));
      // d mod (q-1)
      BigInteger dq = rsaPrivateKey.getPrivateExponent().mod(rsaPrivateKey.getPrimeQ().subtract(BigInteger.valueOf(1)));

      key.dp = base64EncodeUint(dp);
      key.dq = base64EncodeUint(dq);
    }

    if (privateKey instanceof ECPrivateKey ecPrivateKey) {
      key.crv = getCurveOID(privateKey);
      if (key.crv != null) {
        switch (key.crv) {
          case "P-256":
            key.alg = Algorithm.ES256;
            break;
          case "P-384":
            key.alg = Algorithm.ES384;
            break;
          case "P-521":
            key.alg = Algorithm.ES512;
            break;
        }
      }

      int byteLength = getCoordinateLength(ecPrivateKey);
      key.d = base64EncodeUint(ecPrivateKey.getS(), byteLength);
      key.x = base64EncodeUint(ecPrivateKey.getParams().getGenerator().getAffineX(), byteLength);
      key.y = base64EncodeUint(ecPrivateKey.getParams().getGenerator().getAffineY(), byteLength);
    } else if (privateKey instanceof EdECPrivateKey edPrivateKey) {
      key.crv = getCurveOID(edPrivateKey);
      key.alg = Algorithm.fromName(key.crv);

      var privateKeyBytes = edPrivateKey.getBytes().orElseThrow(() -> new JSONWebKeyBuilderException("Unable to obtain the private key bytes."));
      key.d = Base64.getUrlEncoder().withoutPadding().encodeToString(privateKeyBytes);
      try {
        byte[] publicKeyBytes = KeyUtils.deriveEdDSAPublicKeyFromPrivate(privateKeyBytes, key.crv);
        key.x = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes);
      } catch (Exception e) {
        throw new JSONWebKeyBuilderException("Unable to build the public key for the EdDSA private key using curve [" + key.crv + "]", e);
      }
    }

    return key;
  }

  private String getCurveOID(Key key) {
    try {
      return KeyUtils.getCurveName(key);
    } catch (Exception e) {
      throw new JSONWebKeyBuilderException("Unable to read the Object Identifier of the public key.", e);
    }
  }

  /**
   * Build a JSON Web Key from the provided PublicKey.
   *
   * @param publicKey the public key
   * @return a JSON Web Key
   */
  public JSONWebKey build(PublicKey publicKey) {
    Objects.requireNonNull(publicKey);
    JSONWebKey key = new JSONWebKey();

    key.kty = getKeyType(publicKey);
    key.use = "sig";
    if (publicKey instanceof RSAPublicKey rsaPublicKey) {
      key.e = base64EncodeUint(rsaPublicKey.getPublicExponent());
      key.n = base64EncodeUint(rsaPublicKey.getModulus());
    } else if (key.kty == KeyType.EC) {
      ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
      key.crv = getCurveOID(ecPublicKey);

      int length = KeyUtils.getKeyLength(publicKey);
      if (length == 256) {
        key.alg = Algorithm.ES256;
      } else if (length == 384) {
        key.alg = Algorithm.ES384;
      } else if (length == 521) {
        key.alg = Algorithm.ES512;
      }

      int byteLength = getCoordinateLength(ecPublicKey);
      key.x = base64EncodeUint(ecPublicKey.getW().getAffineX(), byteLength);
      key.y = base64EncodeUint(ecPublicKey.getW().getAffineY(), byteLength);
    } else if (key.kty == KeyType.OKP) {
      key.crv = getCurveOID(publicKey);
      key.alg = Algorithm.fromName(key.crv);

      // Intentionally not returning the y coordinate for an Ed25519 or Ed448 key.
      // - The x coordinate contains the complete public key. This contains the y coordinate
      //   and a single bit indicating the sign of the x coordinate.
      int keyLength = KeyUtils.getKeyLength(publicKey);
      byte[] publicKeyBytes;
      try {
        var sequence = new DerInputStream(publicKey.getEncoded()).getSequence();
        publicKeyBytes = sequence[1].toByteArray();
      } catch (DerDecodingException e) {
        throw new JSONWebKeyBuilderException("Unable to read the public key from the DER encoded key.", e);
      }

      key.x = base64EncodeUint(new BigInteger(publicKeyBytes), keyLength);
    }

    return key;
  }

  /**
   * Build a JSON Web Key from the provided X.509 Certificate.
   *
   * @param certificate the certificate
   * @return a JSON Web Key
   */
  public JSONWebKey build(Certificate certificate) {
    Objects.requireNonNull(certificate);
    JSONWebKey key = build(certificate.getPublicKey());
    if (certificate instanceof X509Certificate x509Certificate) {
      if (key.alg == null) {
        key.alg = determineKeyAlgorithm(x509Certificate);
      }

      try {
        String encodedCertificate = new String(Base64.getEncoder().encode(certificate.getEncoded()));
        key.x5c = Collections.singletonList(encodedCertificate);
        key.x5t = JWTUtils.generateJWS_x5t(encodedCertificate);
        key.x5t_256 = JWTUtils.generateJWS_x5t("SHA-256", encodedCertificate);
      } catch (CertificateEncodingException e) {
        throw new JSONWebKeyBuilderException("Failed to decode X.509 certificate.", e);
      }
    }
    return key;
  }

  private int getCoordinateLength(ECKey key) {
    return (int) Math.ceil(key.getParams().getCurve().getField().getFieldSize() / 8d);
  }

  private Algorithm determineKeyAlgorithm(X509Certificate x509Certificate) {
    String sigAlgName = x509Certificate.getSigAlgName();
    Algorithm result = Algorithm.fromName(sigAlgName);
    if (result != null) {
      return result;
    }

    // The JCA reports RSASSA-PSS, while BC will report the actual algorithm such as SHA256withRSAandMGF1.
    // - Java really makes you work for it. Dig out the digest OID to identify the algorithm.
    if ("RSASSA-PSS".equals(sigAlgName)) {
      byte[] encodedBytes = x509Certificate.getSigAlgParams();
      try {
        String oid = new DerInputStream(new DerInputStream(encodedBytes)
            .getSequence()[1].toByteArray())
            .getSequence()[1]
            .getOID().toString();

        result = switch (oid) {
          case ObjectIdentifier.SHA256 -> Algorithm.PS256; // SHA256withRSAandMGF1
          case ObjectIdentifier.SHA384 -> Algorithm.PS384; // SHA384withRSAandMGF1
          case ObjectIdentifier.SHA512 -> Algorithm.PS512; // SHA512withRSAandMGF1
          default -> null;
        };
      } catch (IOException e) {
        throw new JSONWebKeyBuilderException("Failed to decode X.509 certificate signature algorithm parameters to determine the key type.", e);
      }
    }

    return result;
  }

  private KeyType getKeyType(Key key) {
    return switch (key.getAlgorithm()) {
      case "RSA", "RSASSA-PSS" -> KeyType.RSA;
      case "EC" -> KeyType.EC;
      // JCE returns EdDSA, and BC returns Ed25519 or Ed448 respectively
      case "EdDSA", "Ed25519", "Ed448" -> KeyType.OKP;
      default -> null;
    };
  }
}
