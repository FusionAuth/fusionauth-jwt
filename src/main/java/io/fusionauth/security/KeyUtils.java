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

package io.fusionauth.security;

import java.security.Key;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;

/**
 * @author Daniel DeGroff
 */
public class KeyUtils {

  /**
   * Return the length of the key in bits.
   *
   * @param key the key
   * @return the length in bites of the provided key.
   */
  public static int getKeyLength(Key key) {
    if (key instanceof ECKey) {
      int bytes;
      if (key instanceof ECPublicKey) {
        ECPublicKey ecPublicKey = (ECPublicKey) key;
        bytes = ecPublicKey.getW().getAffineX().toByteArray().length;
      } else {
        ECPrivateKey ecPrivateKey = (ECPrivateKey) key;
        bytes = ecPrivateKey.getS().toByteArray().length;
      }

      if (bytes >= 63 && bytes <= 66) {
        return 521;
      }

      // If bytes is not a multiple of 8, add one byte
      if (bytes % 8 != 0) {
        bytes = bytes + 1;
      }

      return ((bytes / 8) * 8) * 8;
    } else if (key instanceof RSAKey) {
      return ((RSAKey) key).getModulus().bitLength();
    }

    throw new IllegalArgumentException();
  }
}
