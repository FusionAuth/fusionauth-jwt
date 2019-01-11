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

package io.fusionauth.jwt.ec;

import io.fusionauth.der.DerInputStream;
import io.fusionauth.der.DerOutputStream;
import io.fusionauth.der.DerValue;
import io.fusionauth.der.Tag;
import io.fusionauth.jwt.domain.Algorithm;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Handle encoding and decoding an ECDSA signature.
 * <p>
 * The DER encoded ECDSA signature structure is as follows:
 * <pre>
 *                                                                          s byte array
 *                                                                                   |
 *                                                        Length of s byte array     |
 *                                                                             |     |
 *                                                          Integer Tag        |     |
 *                        Sequence Tag                                |        |     |
 *                                  |                                 |        |     |
 * DER Encoded ECDSA Signature:  | 0x30 | lenZ | 0x02 | len(r) | r | 0x02 | len(s) | s
 *                                          |      |       |     |
 *         Length of the remaining byte array      |       |     |
 *                                                 |       |     |
 *                                        Integer Tag      |     |
 *                                                         |     |
 *                                     Length of r byte array    |
 *                                                               |
 * </pre>
 *
 * @author Daniel DeGroff
 */
public class ECDSASignature {
  private byte[] bytes;

  public ECDSASignature(byte[] bytes) {
    this.bytes = bytes;
  }

  /**
   * Accept a DER encoded signature and extract the 'r' and the 's' components of the Elliptic signature.
   *
   * @param algorithm the signature algorithm used
   * @return a byte array containing the 'r' and the 's' elliptic signature components.
   * @throws IOException when $%@! gets real.
   */
  public byte[] derDecode(Algorithm algorithm) throws IOException {
    // Incoming DER Sequence [ r, s ]
    DerValue[] sequence = new DerInputStream(bytes).getSequence();
    byte[] r = sequence[0].getPositiveBigInteger().toByteArray();
    byte[] s = sequence[1].getPositiveBigInteger().toByteArray();

    byte[] result;
    switch (algorithm) {
      case ES256:
        result = new byte[64];
        break;
      case ES384:
        result = new byte[96];
        break;
      case ES512:
        result = new byte[132];
        break;
      default:
        throw new IllegalArgumentException("Unable to decode the signature for algorithm [" + algorithm.name() + "]");
    }

    int len = result.length / 2;
    System.arraycopy(r, r.length > len ? 1 : 0, result, r.length < len ? 1 : 0, r.length > len ? len : r.length);
    System.arraycopy(s, s.length > len ? 1 : 0, result, s.length < len ? (len + 1) : len, s.length > len ? len : s.length);
    return result;
  }

  /**
   * Accept an ECDSA encoded signature of the 'r' and 's' elliptic components, return these values DER encoded.
   *
   * @return a DER encoded sequence containing the 'r' and the 's' elliptic signature components
   * @throws IOException when $%@! gets real.
   */
  public byte[] derEncode() throws IOException {
    // Split the ECDSA encoded signature into two parts, the r and s components
    byte[] r = Arrays.copyOfRange(bytes, 0, bytes.length / 2);
    byte[] s = Arrays.copyOfRange(bytes, bytes.length / 2, bytes.length);

    return new DerOutputStream()
        // DER Sequence [ r, s ]
        .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
            .writeValue(new DerValue(new BigInteger(1, r)))
            .writeValue(new DerValue(new BigInteger(1, s)))))
        .toByteArray();
  }
}
