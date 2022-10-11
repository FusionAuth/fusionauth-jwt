/*
 * Copyright (c) 2022, FusionAuth, All Rights Reserved
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

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import io.fusionauth.der.DerInputStream;
import io.fusionauth.der.DerOutputStream;
import io.fusionauth.der.DerValue;
import io.fusionauth.der.ObjectIdentifier;
import io.fusionauth.der.Tag;
import io.fusionauth.jwt.domain.KeyType;
import io.fusionauth.pem.KeyDecoder;
import io.fusionauth.pem.PEMDecoderException;
import io.fusionauth.pem.domain.PEM;
import static io.fusionauth.pem.domain.PEM.EC_PRIVATE_KEY_PREFIX;
import static io.fusionauth.pem.domain.PEM.EC_PRIVATE_KEY_SUFFIX;

/**
 * @author Daniel DeGroff
 */
public class ECKeyDecoder implements KeyDecoder {
  public static final String oid = ObjectIdentifier.EC_ENCRYPTION;

  private static final byte[] EC_ENCRYPTION_OID = new byte[]{(byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xCE, (byte) 0x3D, (byte) 0x02, (byte) 0x01};

  @Override
  public PEM decode(PrivateKey privateKey, DerValue[] sequence)
      throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException {
    if (sequence.length != 3 || !sequence[0].tag.is(Tag.Integer) || !sequence[1].tag.is(Tag.Sequence) || !sequence[2].tag.is(Tag.OctetString)) {
      // Expect the following format : [ Integer | Sequence | OctetString ]
      throw new InvalidKeyException("Could not decode the private key. Expecting values in the DER encoded sequence in the following format [ Integer | Sequence | OctetString ]");
    }

    // SEQUENCE (3 elem)
    //   INTEGER 0
    //   SEQUENCE (2 elem)
    //     OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
    //     OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1 (ANSI X9.62 named elliptic curve)
    //   OCTET STRING (109 byte) 306B02010104207AF6732F581D005AFCF216F6385FF6371029242CC60840DD7D2A7A5…
    //     SEQUENCE (3 elem)
    //       INTEGER 1
    //       OCTET STRING (32 byte) 7AF6732F581D005AFCF216F6385FF6371029242CC60840DD7D2A7A5503B7D21C
    //       [1] (1 elem)
    //          BIT STRING (520 bit) 0000010000010001010110110011111110100011100111111010111001000001101101…

    DerValue[] privateKeySequence = new DerInputStream(sequence[2]).getSequence();
    if (privateKeySequence.length == 3 && privateKeySequence[2].tag.rawByte == (byte) 0xA1) {
      DerValue bitString = new DerInputStream(privateKeySequence[2]).readDerValue();
      byte[] encodedPublicKey = getEncodedPublicKeyFromPrivate(bitString.toByteArray(), privateKey.getEncoded());
      PublicKey publicKey = KeyFactory.getInstance(KeyType.EC.algorithm).generatePublic(new X509EncodedKeySpec(encodedPublicKey));

      return new PEM(privateKey, publicKey);
    } else {
      // The private key did not contain the public key
      return new PEM(privateKey);
    }
  }

  @Override
  public PEM decode(String encoded) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
    byte[] bytes = getKeyBytes(encoded, EC_PRIVATE_KEY_PREFIX, EC_PRIVATE_KEY_SUFFIX);
    DerValue[] sequence = new DerInputStream(bytes).getSequence();
    BigInteger version = sequence[0].getBigInteger();

    // Expecting this EC private key to be version 1, it is not encapsulated in a PKCS#8 container
    if (!version.equals(BigInteger.valueOf(1))) {
      throw new PEMDecoderException("Expected version [1] but found version of [" + version + "]");
    }

    // This is an EC private key, encapsulate it in a PKCS#8 format to be compatible with the Java Key Factory
    //
    // EC Private key
    // ------------------------------------------------------
    // PrivateKeyInfo ::= SEQUENCE {
    //   version         Version,
    //   PrivateKey      OCTET STRING
    //   [0] parameters  Context Specific
    //     curve           OBJECT IDENTIFIER
    //   [1] publicKey   Context Specific
    //                     BIT STRING
    // }
    //

    // Convert it to:
    //
    // DER Encoded PKCS#8  - version 0
    // ------------------------------------------------------
    // PrivateKeyInfo ::= SEQUENCE {
    //   version         Version,
    //   algorithm       AlgorithmIdentifier,
    //   PrivateKey      OCTET STRING
    // }
    //
    // AlgorithmIdentifier ::= SEQUENCE {
    //   algorithm       OBJECT IDENTIFIER,
    //   parameters      ANY DEFINED BY algorithm OPTIONAL
    // }

    if (sequence.length == 2) {
      // This is an EC encoded key w/out the context specific values [0] or [1] - this means we don't
      // have enough information to build a PKCS#8 key.
      throw new PEMDecoderException("Unable to decode the provided PEM, the EC private key does not contain the"
                                    + " curve identifier necessary to convert to a PKCS#8 format before building a private key");
    }

    ObjectIdentifier curveOID = sequence[2].getOID();
    DerOutputStream pkcs_8 = new DerOutputStream()
        .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
            .writeValue(new DerValue(BigInteger.valueOf(0))) // Always version 0
            .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
                .writeValue(new DerValue(Tag.ObjectIdentifier, EC_ENCRYPTION_OID))
                .writeValue(new DerValue(Tag.ObjectIdentifier, curveOID.value))))
            .writeValue(new DerValue(Tag.OctetString, bytes))));

    ECPrivateKey privateKey = (ECPrivateKey) KeyFactory.getInstance(KeyType.EC.algorithm).generatePrivate(new PKCS8EncodedKeySpec(pkcs_8.toByteArray()));

    // Extract the public key from the PEM
    DerValue bitString = new DerInputStream(sequence[3]).readDerValue();
    byte[] encodedPublicKey = getEncodedPublicKeyFromPrivate(bitString.toByteArray(), privateKey.getEncoded());
    PublicKey publicKey = KeyFactory.getInstance(KeyType.EC.algorithm).generatePublic(new X509EncodedKeySpec(encodedPublicKey));

    // The publicKey may be null if it was not found in the private key
    return new PEM(privateKey, publicKey);
  }

  @Override
  public KeyType keyType() {
    return KeyType.EC;
  }
}
