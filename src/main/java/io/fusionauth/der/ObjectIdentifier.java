/*
 * Copyright (c) 2018-2022, FusionAuth, All Rights Reserved
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

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

import io.fusionauth.domain.Buildable;

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

  /**
   * Encode a string OID into a DER encoded byte array.
   *
   * @param oid the string Object Identifier
   * @return a DER encoded byte array
   */
  public static byte[] encodeInt(String oid) {
    String[] parts = oid.trim().split("\\.");
    int[] ints = new int[parts.length];

    for (int i = 0; i < parts.length; i++) {
      ints[i] = Integer.parseInt(parts[i]);
    }

    // 0x28 - 40 decimal
    ByteBuffer buf = ByteBuffer.allocate(ints.length * 4);
    if (ints[0] < 2) {
      buf.put((byte) ((ints[0] * 0x28) + ints[1]));
    } else {
      int i = (ints[0] * 0x28) + ints[1];
      buf.put(encodeInt(i));
    }
    for (int i = 2; i < ints.length; i++) {
      int r = ints[i];
      byte[] r2 = encodeInt(r);
      buf.put(r2);
    }

    return Arrays.copyOfRange(buf.array(), 0, buf.position());
  }

  private static byte[] encodeInt(int n) {
    byte[] buf = new byte[4];
    int i = 0;
    while (n != 0) {
      if (i > 0) {
        // 0x7F - 127 decimal
        // 0x80 - 128 decimal
        buf[i++] = (byte) ((n & 0x7F) | 0x80);
      } else {
        buf[i++] = (byte) (n & 0x7F);
      }
      n >>>= 7;
    }

    byte[] result = new byte[i];
    for (int j = 0; j < result.length; j++) {
      result[j] = buf[--i];
    }

    if (result.length == 0) {
      return new byte[1];
    }

    return result;
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
    if (this == o) {
      return true;
    }
    if (!(o instanceof ObjectIdentifier)) {
      return false;
    }
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

      // Skip multibyte length leading bytes, we'll handle them on the next pass
      // - 0x80 - 128 decimal
      if ((b & 0x80) != 0) {
        continue;
      }

      // Add a separator between nodes
      if (index != 0) {
        sb.append('.');
      }

      // Use an int to build the next node value, it may be made up of multiple bytes
      int node = 0;

      // Make at least one pass, optionally catch up the index to the cursor 'i' if we skipped a byte
      // - 0x7F - 127 decimal
      for (int j = index; j <= i; ++j) {
        node = node << 7;
        node = node | value[j] & 0x7F;
      }

      // The first two nodes are encoded in a single byte when the node is less than 0x50 (80 decimal)
      // - 0x28 - 40 decimal
      // - 0x50 - 80 decimal
      if (index == 0) {
        if (node < 80) {
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
