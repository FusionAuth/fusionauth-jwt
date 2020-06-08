/*
 * Copyright (c) 2020, FusionAuth, All Rights Reserved
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

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;

/**
 * @author Daniel DeGroff
 */
public class JWKUtils {
  /**
   * Decode an un-signed integer from a <code>String</code> to a <code>BigInteger</code> object.
   *
   * @param encoded the encoded integer
   * @return a <code>BigInteger</code> representation of the encoded value.
   */
  public static BigInteger base64DecodeUint(String encoded) {
    byte[] bytes = Base64.getUrlDecoder().decode(encoded);
    if (bytes.length % 8 == 0 && bytes[0] != 0) {
      byte[] copy = new byte[bytes.length + 1];
      copy[0] = 0;
      System.arraycopy(bytes, 0, copy, 1, bytes.length);
      return new BigInteger(copy);
    }

    return new BigInteger(bytes);
  }

  /**
   * Encode an un-signed integer from a <code>BigInteger</code> to a <code>String</code>.
   *
   * @param value the integer value
   * @return a Base64 encoded value of the un-signed integer.
   */
  public static String base64EncodeUint(BigInteger value) {
    return base64EncodeUint(value, -1);
  }

  /**
   * Encode an un-signed integer from a <code>BigInteger</code> to a <code>String</code>.
   *
   * @param value         the integer value
   * @param minimumLength the minimum length of the returned value. A value of -1 indicates there is no minimum.
   * @return a Base64 encoded value of the un-signed integer.
   */
  public static String base64EncodeUint(BigInteger value, int minimumLength) {
    if (value.signum() < 0) {
      throw new JSONWebKeyBuilderException("Illegal parameter, cannot encode a negative number.", new IllegalArgumentException());
    }

    byte[] bytes = value.toByteArray();
    if ((value.bitLength() % 8 == 0) && (bytes[0] == 0) && bytes.length > 1) {
      bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
    }

    if (minimumLength != -1) {
      if (bytes.length < minimumLength) {
        byte[] buf = new byte[minimumLength];
        System.arraycopy(bytes, 0, buf, (minimumLength - bytes.length), bytes.length);
        bytes = buf;
      }
    }

    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
