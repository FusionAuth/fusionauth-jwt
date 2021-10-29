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

package io.fusionauth.der;

import io.fusionauth.domain.Buildable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * @author Daniel DeGroff
 */
public class ObjectIdentifier implements Buildable<ObjectIdentifier> {
  /**
   * Elliptic curve / 256 bit / secp256r1 / prime256v1
   * X9.62/SECG curve over a 256 bit prime field
   */
  public static final String ECDSA_P256 = "1.2.840.10045.3.1.7";

  /**
   * Elliptic curve / 384 bit / secp384r1 / prime384v1
   * NIST/SECG curve over a 384 bit prime field
   */
  public static final String ECDSA_P384 = "1.3.132.0.34";

  /**
   * Elliptic curve / 512 bit / secp521r1 / prime521v1
   * NIST/SECG curve over a 521 bit prime field
   */
  public static final String ECDSA_P521 = "1.3.132.0.35";

  /**
   * Elliptic Curve Public Key cryptography
   */
  public static final String EC_ENCRYPTION = "1.2.840.10045.2.1";

  /**
   * RSA Public Key cryptography
   */
  public static final String RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

  /**
   * RSA Encryption / SHA-256 / SHA256withRSA
   */
  public static final String RSA_SHA256 = "1.2.840.113549.1.1.11";

  /**
   * RSA Encryption / SHA-384 / SHA384withRSA
   */
  public static final String RSA_SHA384 = "1.2.840.113549.1.1.12";

  /**
   * RSA Encryption / SHA-512 / SHA512withRSA
   */
  public static final String RSA_SHA512 = "1.2.840.113549.1.1.13";

  /**
   * X.520 DN component - Common Name
   */
  public static final String X_520_DN_COMMON_NAME = "2.5.4.3";

  /**
   * The raw byte array of this Object Identifier.
   */
  public byte[] value;

  /**
   * The string form of the byte array after it has been decoded.
   */
  private String decoded;

  public ObjectIdentifier(byte[] value) {
    this.value = value;
  }

  public static byte[] encode(String s) {
    String[] parts = s.trim().split("\\.");
    List<Integer> result = new ArrayList<>();

    for (int a = 0, b, i = 0; i < parts.length; i++) {
      if (i == 0) {
        a = Integer.parseInt(parts[i]);
      } else if (i == 1) {
        result.add(40 * a + Integer.parseInt(parts[i]));
      } else {
        b = Integer.parseInt(parts[i]);
        if (b < 128) {
          result.add(b);
        } else {
          result.add(128 + (b / 128));
          result.add(b % 128);
        }
      }
    }

    byte[] bytes = new byte[result.size()];
    for (int i = 0; i < result.size(); i++) {
      bytes[i] = result.get(i).byteValue();
    }

    return bytes;
  }

  /**
   * Decode the byte array for this Object Identifier.
   *
   * @return a string representation of the OID.
   * @throws DerDecodingException if the byte array is not encoded properly.
   */
  public String decode() throws DerDecodingException {
    if (decoded == null) {
      _decode();
    }

    return decoded;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof ObjectIdentifier)) return false;
    ObjectIdentifier that = (ObjectIdentifier) o;
    return Arrays.equals(value, that.value) &&
        Objects.equals(decoded, that.decoded);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(decoded);
    result = 31 * result + Arrays.hashCode(value);
    return result;
  }

  @Override
  public String toString() {
    try {
      return decode();
    } catch (DerDecodingException e) {
      return "Failed to _decode this object, unable to produce a string.";
    }
  }

  private void _decode() throws DerDecodingException {
    StringBuilder sb = new StringBuilder(value.length * 4);
    int index = 0;

    for (int i = 0; i < value.length; i++) {
      // We are not currently handling OIDs that have a node larger than 4 bytes
      if (i - index + 1 > 4) {
        throw new DerDecodingException("The object identifier contains a node that is larger than 4 bytes. This is not currently supported using this library.");
      }

      byte b = value[i];

      // Skip multi-byte length leading bytes, we'll handle them on the next pass
      if ((b & 128) != 0) {
        continue;
      }

      // Add a separator between nodes
      if (index != 0) {
        sb.append('.');
      }

      // Use an int to build the next node value, it may be made up of multiple bytes
      int node = 0;

      // Make at least one pass, optionally catch up the index to the cursor 'i' if we skipped a byte
      for (int j = index; j <= i; ++j) {
        node = node << 7;
        node = node | value[j] & 127;
      }

      // The first two nodes are encoded in a single byte when the node is less than 0x50 (80 decimal)
      if (index == 0) {
        if (node < 0x50) {
          sb.append(node / 40)
              .append('.')
              .append(node % 40);
        } else {
          sb.append("2.")
              .append(node - 80);
        }
      } else {
        sb.append(node);
      }

      index = i + 1;
    }

    decoded = sb.toString();
  }
}
