/*
 * Copyright (c) 2018-2023, FusionAuth, All Rights Reserved
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

package io.fusionauth.pem;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

import io.fusionauth.der.DerInputStream;
import io.fusionauth.der.DerValue;
import io.fusionauth.der.ObjectIdentifier;
import io.fusionauth.der.Tag;
import io.fusionauth.jwt.domain.KeyType;
import io.fusionauth.pem.domain.PEM;
import static io.fusionauth.pem.domain.PEM.EC_PRIVATE_KEY_SUFFIX;
import static io.fusionauth.pem.domain.PEM.PKCS_1_PRIVATE_KEY_PREFIX;
import static io.fusionauth.pem.domain.PEM.PKCS_1_PUBLIC_KEY_PREFIX;
import static io.fusionauth.pem.domain.PEM.PKCS_1_PUBLIC_KEY_SUFFIX;
import static io.fusionauth.pem.domain.PEM.PKCS_8_PRIVATE_KEY_PREFIX;
import static io.fusionauth.pem.domain.PEM.PKCS_8_PRIVATE_KEY_SUFFIX;
import static io.fusionauth.pem.domain.PEM.X509_CERTIFICATE_PREFIX;
import static io.fusionauth.pem.domain.PEM.X509_CERTIFICATE_SUFFIX;
import static io.fusionauth.pem.domain.PEM.X509_PUBLIC_KEY_PREFIX;
import static io.fusionauth.pem.domain.PEM.X509_PUBLIC_KEY_SUFFIX;

/**
 * @author Daniel DeGroff
 */
public class PEMDecoder {
  /**
   * Decode a PEM and extract the public or private keys. If the encoded private key contains the public key, the returned
   * PEM object will contain both keys.
   *
   * @param path the path to the encoded PEM file
   * @return a PEM object containing a public or private key, or both
   */
  public PEM decode(Path path) {
    Objects.requireNonNull(path);

    try {
      return decode(Files.readAllBytes(path));
    } catch (IOException e) {
      throw new PEMDecoderException("Unable to read the file from path [" + path.toAbsolutePath() + "]", e);
    }
  }

  /**
   * Decode a PEM and extract the public or private keys. If the encoded private key contains the public key, the returned
   * PEM object will contain both keys.
   *
   * @param bytes the byte array of the encoded PEM file
   * @return a PEM object containing a public or private key, or both
   */
  public PEM decode(byte[] bytes) {
    Objects.requireNonNull(bytes);
    return decode(new String(bytes));
  }

  /**
   * Decode a PEM and extract the public or private keys. If the encoded private key contains the public key, the returned
   * PEM object will contain both keys.
   *
   * @param encodedKey the string representation the encoded PEM
   * @return a PEM object containing a public or private key, or both
   */
  public PEM decode(String encodedKey) {
    Objects.requireNonNull(encodedKey);

    // TODO : Get a decoder based upon the PEM headers

    try {
      if (encodedKey.contains(PKCS_1_PUBLIC_KEY_PREFIX)) {
        return decode_PKCS_1_Public(encodedKey);
      } else if (encodedKey.contains(X509_PUBLIC_KEY_PREFIX)) {
        return decode_X_509(encodedKey);
      } else if (encodedKey.contains(X509_CERTIFICATE_PREFIX)) {
        return new PEM(CertificateFactory.getInstance("X.509").generateCertificate(
            new ByteArrayInputStream(getKeyBytes(encodedKey, X509_CERTIFICATE_PREFIX, X509_CERTIFICATE_SUFFIX))));
      } else if (encodedKey.contains(PKCS_1_PRIVATE_KEY_PREFIX)) {
        return KeyDecoder.getByType(KeyType.RSA.name).decode(encodedKey);
      } else if (encodedKey.contains(PKCS_8_PRIVATE_KEY_PREFIX)) {
        return decode_PKCS_8(encodedKey);
      } else if (encodedKey.contains(EC_PRIVATE_KEY_SUFFIX)) {
        return KeyDecoder.getByType(KeyType.EC.name).decode(encodedKey);
      } else {
        throw new PEMDecoderException(new InvalidParameterException("Unexpected PEM Format"));
      }
    } catch (CertificateException | InvalidKeyException | InvalidKeySpecException | IOException | NoSuchAlgorithmException e) {
      throw new PEMDecoderException(e);
    }
  }

  private PEM decode_PKCS_1_Public(String encodedKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    byte[] bytes = getKeyBytes(encodedKey, PKCS_1_PUBLIC_KEY_PREFIX, PKCS_1_PUBLIC_KEY_SUFFIX);
    DerValue[] sequence = new DerInputStream(bytes).getSequence();

    // DER Encoded PKCS#1 structure
    // ------------------------------------------------------
    // RSAPublicKey ::= SEQUENCE {
    //   modulus           INTEGER,  -- n
    //   publicExponent    INTEGER   -- e
    // }

    if (sequence.length != 2 || !sequence[0].tag.is(Tag.Integer) || !sequence[1].tag.is(Tag.Integer)) {
      // Expect the following format : [ Integer | Integer ]
      throw new InvalidKeyException("Could not build this PKCS#1 public key. Expecting values in the DER encoded sequence in the following format [ Integer | Integer ]");
    }

    BigInteger modulus = sequence[0].getBigInteger();
    BigInteger publicExponent = sequence[1].getBigInteger();
    return new PEM(KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent)));
  }

  private PEM decode_PKCS_8(String encodedKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException {
    byte[] bytes = getKeyBytes(encodedKey, PKCS_8_PRIVATE_KEY_PREFIX, PKCS_8_PRIVATE_KEY_SUFFIX);
    DerValue[] sequence = new DerInputStream(bytes).getSequence();

    // DER Encoded PKCS#8
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

    ObjectIdentifier algorithmOID = new DerInputStream(sequence[1].toByteArray()).getOID();
    String oid = algorithmOID.decode();

    KeyDecoder keyDecoder = KeyDecoder.getByOID(oid);
    PrivateKey privateKey = KeyFactory.getInstance(keyDecoder.keyType().algorithm).generatePrivate(new PKCS8EncodedKeySpec(bytes));
    return keyDecoder.decode(privateKey, sequence);
  }

  private PEM decode_X_509(String encodedKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    byte[] bytes = getKeyBytes(encodedKey, X509_PUBLIC_KEY_PREFIX, X509_PUBLIC_KEY_SUFFIX);
    DerValue[] sequence = new DerInputStream(bytes).getSequence();

    // DER Encoded Public Key Format SubjectPublicKeyInfo
    // ------------------------------------------------------
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm         AlgorithmIdentifier,
    //   subjectPublicKey  BIT STRING
    // }
    //
    // AlgorithmIdentifier ::= SEQUENCE {
    //   algorithm       OBJECT IDENTIFIER,
    //   parameters      ANY DEFINED BY algorithm OPTIONAL
    // }

    if (sequence.length != 2 || !sequence[0].tag.is(Tag.Sequence) || !sequence[1].tag.is(Tag.BitString)) {
      // Expect the following format : [ Sequence | BitString ]
      throw new InvalidKeyException("Could not decode the X.509 public key. Expected values in the DER encoded sequence in the following format [ Sequence | BitString ]");
    }

    DerInputStream der = new DerInputStream(sequence[0].toByteArray());
    ObjectIdentifier algorithmOID = der.getOID();

    KeyType type = KeyType.lookupByOID(algorithmOID.decode());
    return new PEM(KeyFactory.getInstance(type.algorithm).generatePublic(new X509EncodedKeySpec(bytes)));
  }

  private byte[] getKeyBytes(String key, String keyPrefix, String keySuffix) {
    int startIndex = key.indexOf(keyPrefix);
    int endIndex = key.indexOf(keySuffix);

    String base64 = key.substring(startIndex + keyPrefix.length(), endIndex).replaceAll("\\s+", "");
    return Base64.getDecoder().decode(base64);
  }
}
