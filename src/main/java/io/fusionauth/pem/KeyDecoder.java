/*
 * Copyright (c) 2022-2023, FusionAuth, All Rights Reserved
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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Objects;
import java.util.ServiceLoader;

import io.fusionauth.der.DerInputStream;
import io.fusionauth.der.DerOutputStream;
import io.fusionauth.der.DerValue;
import io.fusionauth.der.Tag;
import io.fusionauth.jwt.MissingKeyDecoderException;
import io.fusionauth.jwt.SafeServiceLoader;
import io.fusionauth.jwt.domain.KeyType;
import io.fusionauth.jwt.spi.KeyDecoderProvider;
import io.fusionauth.pem.domain.PEM;

/**
 * A key decoder. An instance of a KeyDecoder may be re-used, all implementations must be thread safe.
 *
 * @author Daniel DeGroff
 */
public interface KeyDecoder {
  ServiceLoader<KeyDecoderProvider> loader = SafeServiceLoader.load(KeyDecoderProvider.class);

  static KeyDecoder getByOID(String oid) {
    Objects.requireNonNull(oid);

    for (KeyDecoderProvider provider : loader) {
      KeyDecoder keyDecoder = provider.get();
      if (keyDecoder.keyType().oid.equals(oid)) {
        return keyDecoder;
      }
    }

    throw new MissingKeyDecoderException("There are no Key Decoders registered for OID [" + oid + "].");
  }

  static KeyDecoder getByType(String name) {
    Objects.requireNonNull(name);

    for (KeyDecoderProvider provider : loader) {
      KeyDecoder keyDecoder = provider.get();
      if (keyDecoder.keyType().name.equals(name)) {
        return keyDecoder;
      }
    }

    throw new MissingKeyDecoderException("There are no Key Decoders registered for key type [" + name + "].");
  }

  /**
   * Decode a private key into a PEM.
   *
   * @param privateKey the private key to decode
   * @param sequence   the PKCS#8 DER encoded sequence
   * @return a PEM object
   * @throws InvalidKeySpecException  there is a bug in the code.
   * @throws IOException              this can't be good.
   * @throws NoSuchAlgorithmException this is probably your fault.
   */
  PEM decode(PrivateKey privateKey, DerValue[] sequence) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException, InvalidKeyException;

  /**
   * Decode a PEM encoded private key into a PEM object.
   *
   * @param encoded the PEM encoded string
   * @return a PEM object
   * @throws InvalidKeySpecException  there is a bug in the code.
   * @throws IOException              this can't be good.
   * @throws NoSuchAlgorithmException this is probably your fault.
   */
  PEM decode(String encoded) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException;

  /**
   * Return an X.509 DER encoded byte array of the public key info.
   *
   * @param bytes      the public key byte array
   * @param encodedKey the private key byte array
   * @return a DER encoded byte array
   * @throws IOException if $@%^ gets real.
   */
  default byte[] getEncodedPublicKeyFromPrivate(byte[] bytes, byte[] encodedKey) throws IOException {
    // Build an X.509 DER encoded byte array from the provided bitString
    //
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm         AlgorithmIdentifier,
    //   subjectPublicKey  BIT STRING
    // }
    DerValue[] sequence = new DerInputStream(encodedKey).getSequence();
    return new DerOutputStream()
        .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
            .writeValue(new DerValue(Tag.Sequence, sequence[1].toByteArray()))
            .writeValue(new DerValue(Tag.BitString, bytes))))
        .toByteArray();
  }

  /**
   * Return the base64 decoded bytes from the PEM encoded key.
   *
   * @param key       the PEM encoded key
   * @param keyPrefix the PEM prefix
   * @param keySuffix the PEM suffix
   * @return a decoded byte array of the key bytes
   */
  default byte[] getKeyBytes(String key, String keyPrefix, String keySuffix) {
    int startIndex = key.indexOf(keyPrefix);
    int endIndex = key.indexOf(keySuffix);

    String base64 = key.substring(startIndex + keyPrefix.length(), endIndex).replaceAll("\\s+", "");
    return Base64.getDecoder().decode(base64);
  }

  /**
   * @return the key type for this decoder.
   */
  KeyType keyType();
}
