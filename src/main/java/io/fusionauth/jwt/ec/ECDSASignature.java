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
  private final byte[] bytes;

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

    // The length of the result is fixed and discrete per algorithm.
    byte[] result = switch (algorithm) {
      case ES256 -> new byte[64];
      case ES384 -> new byte[96];
      case ES512 -> new byte[132];
      default ->
          throw new IllegalArgumentException("Unable to decode the signature for algorithm [" + algorithm.name() + "]");
    };

    // Because the response is not encoded, the r and s component must take up an equal amount of the resulting array.
    // This allows the consumer of this value to always safely split the value in half based upon an index value since
    // the result is not encoded and does not contain any meta-data about the contents.
    int componentLength = result.length / 2;

    // The extracted byte array of the DER encoded value can be left padded. For this reason, the component lengths
    // may be greater than componentLength which is half of the result. So for example, if r is left padded, the
    // length may be equal to 67 in ES512 even though componentLength is only 66. This is why we must calculate the
    // source position for reading when we copy the r byte array into the result. The same is potentially true for
    // either component. We cannot make an assumption that the source position in r or s will be 0.
    //
    // Similarly, when the r and s components are not padded, but they are shorter than componentLength, we need to
    // pad the value to be right aligned in the result. This is why the destination position may not be 0 or
    // componentLength respectively for
    // r and s.
    //
    // If s is 65 bytes, then the destination position in the 0 initialized resulting array needs to be
    // componentLength + 1 so that we write the final byte of s at the end of the result.
    //
    // For clarity, calculate each input to the arraycopy method first.

    int rSrcPos = r.length > componentLength ? (r.length - componentLength) : 0;
    int rDstPos = Math.max(0, componentLength - r.length);
    int rLength = Math.min(r.length, componentLength);
    System.arraycopy(r, rSrcPos, result, rDstPos, rLength);

    int sSrcPos = s.length > componentLength ? (s.length - componentLength) : 0;
    int sDstPos = s.length < componentLength ? (componentLength + (componentLength - s.length)) : componentLength;
    int sLength = Math.min(s.length, componentLength);
    System.arraycopy(s, sSrcPos, result, sDstPos, sLength);

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
