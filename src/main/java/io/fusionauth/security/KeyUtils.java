/*
 * Copyright (c) 2020-2025, FusionAuth, All Rights Reserved
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

package io.fusionauth.security;

import io.fusionauth.der.DerInputStream;
import io.fusionauth.der.DerValue;
import io.fusionauth.der.ObjectIdentifier;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

import static io.fusionauth.der.ObjectIdentifier.ECDSA_P256;
import static io.fusionauth.der.ObjectIdentifier.ECDSA_P384;
import static io.fusionauth.der.ObjectIdentifier.ECDSA_P521;
import static io.fusionauth.der.ObjectIdentifier.EdDSA_25519;
import static io.fusionauth.der.ObjectIdentifier.EdDSA_448;

/**
 * @author Daniel DeGroff
 */
public class KeyUtils {
  /**
   * @param key the key
   * @return the name of the curve used by the key or null if it cannot be identified.
   */
  public static String getCurveName(Key key) throws IOException {
    // Match up the Curve Object Identifier to a string value
    String oid = getCurveOID(key).decode();
    return switch (oid) {
      case ECDSA_P256 -> "P-256";
      case ECDSA_P384 -> "P-384";
      case ECDSA_P521 -> "P-521";
      case EdDSA_25519 -> "Ed25519";
      case EdDSA_448 -> "Ed448";
      default -> null;
    };
  }

  /**
   * @param key the key
   * @return the Object Identifier (OID) of the curve used by the key.
   */
  public static ObjectIdentifier getCurveOID(Key key) throws IOException {
    DerValue[] sequence = new DerInputStream(key.getEncoded()).getSequence();
    if (key instanceof PrivateKey) {
      if (key instanceof EdECPrivateKey) {
        return sequence[1].getOID();
      }

      // Read the first value in the sequence, it is the algorithm OID, the second will be the curve
      sequence[1].getOID();
      return sequence[1].getOID();
    } else {
      if (key instanceof EdECPublicKey) {
        return sequence[0].getOID();
      }

      // Read the first value in the sequence, it is the algorithm OID, the second will be the curve
      sequence[0].getOID();
      return sequence[0].getOID();
    }
  }

  /**
   * Calculate the public key for the provided EdDSA private key.
   *
   * @param privateKey the private EdDSA key
   * @param curve      the curve used by the private key
   * @return the public key
   */
  public static byte[] deriveEdDSAPublicKeyFromPrivate(byte[] privateKey, String curve) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(curve);
    keyPairGenerator.initialize(new NamedParameterSpec(curve), new SecureRandom() {
      public void nextBytes(byte[] bytes) {
        System.arraycopy(privateKey, 0, bytes, 0, privateKey.length);
      }
    });
    byte[] spki = keyPairGenerator.generateKeyPair().getPublic().getEncoded();
    return Arrays.copyOfRange(spki, spki.length - privateKey.length, spki.length);
  }

  /**
   * Return the length of the key in bits.
   *
   * @param key the key
   * @return the length in bites of the provided key.
   */
  public static int getKeyLength(Key key) {
    if (key instanceof ECKey) {
      int bytes;
      if (key instanceof ECPublicKey ecPublicKey) {
        bytes = ecPublicKey.getW().getAffineX().toByteArray().length;
      } else {
        ECPrivateKey ecPrivateKey = (ECPrivateKey) key;
        bytes = ecPrivateKey.getS().toByteArray().length;
      }

      if (bytes >= 63 && bytes <= 66) {
        return 521;
      }

      // If bytes is not a multiple of 8, add the difference to get to the next 8 byte boundary
      int mod = bytes % 8;
      // Adjust the length for a mod count of anything equal to or greater than 2.
      if (mod >= 2) {
        bytes = bytes + (8 - mod);
      }

      return ((bytes / 8) * 8) * 8;
    } else if (key instanceof RSAKey rsaKey) {
      return rsaKey.getModulus().bitLength();
    } else if (key instanceof EdECKey edECKey) {
      // Only recognizing Ed25519 and Ed448.
      String curve = edECKey.getParams().getName();
      if ("Ed25519".equals(curve)) {
        return 32;
      } else if ("Ed448".equals(curve)) {
        return 57;
      }
    }

    throw new IllegalArgumentException();
  }
}
