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

package io.fusionauth.jwt.rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import io.fusionauth.der.DerInputStream;
import io.fusionauth.der.DerValue;
import io.fusionauth.der.ObjectIdentifier;
import io.fusionauth.jwt.domain.KeyType;
import io.fusionauth.pem.KeyDecoder;
import io.fusionauth.pem.PEMDecoderException;
import io.fusionauth.pem.domain.PEM;
import static io.fusionauth.pem.domain.PEM.PKCS_1_PRIVATE_KEY_PREFIX;
import static io.fusionauth.pem.domain.PEM.PKCS_1_PRIVATE_KEY_SUFFIX;

/**
 * @author Daniel DeGroff
 */
public class RSAKeyDecoder implements KeyDecoder {
  public static final String oid = ObjectIdentifier.RSA_ENCRYPTION;

  @Override
  public PEM decode(PrivateKey privateKey, DerValue[] sequence) throws NoSuchAlgorithmException, InvalidKeySpecException {
    if (privateKey instanceof RSAPrivateCrtKey) {
      BigInteger modulus = ((RSAPrivateCrtKey) privateKey).getModulus();
      BigInteger publicExponent = ((RSAPrivateCrtKey) privateKey).getPublicExponent();
      PublicKey publicKey = KeyFactory.getInstance(KeyType.RSA.algorithm).generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
      return new PEM(privateKey, publicKey);
    }

    // The private key does not contain a public key
    return new PEM(privateKey);
  }

  @Override
  public PEM decode(String encoded) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
    byte[] bytes = getKeyBytes(encoded, PKCS_1_PRIVATE_KEY_PREFIX, PKCS_1_PRIVATE_KEY_SUFFIX);
    DerValue[] sequence = new DerInputStream(bytes).getSequence();

    // DER Encoded PKCS#1 structure
    // https://tools.ietf.org/html/rfc3447#appendix-A.1
    // ------------------------------------------------------
    // RSAPrivateKey ::= SEQUENCE {
    //   version           Version,
    //   modulus           INTEGER,  -- n
    //   publicExponent    INTEGER,  -- e
    //   privateExponent   INTEGER,  -- d
    //   prime1            INTEGER,  -- p
    //   prime2            INTEGER,  -- q
    //   exponent1         INTEGER,  -- d mod (p-1)
    //   exponent2         INTEGER,  -- d mod (q-1)
    //   coefficient       INTEGER,  -- (inverse of q) mod p
    //   otherPrimeInfos   OtherPrimeInfos OPTIONAL
    // }

    if (sequence.length < 9) {
      throw new PEMDecoderException(
          new InvalidKeyException("Could not build a PKCS#1 private key. Expected at least 9 values in the DER encoded sequence."));
    }

    // Ignoring the version value in the sequence
    BigInteger n = sequence[1].getBigInteger();
    BigInteger e = sequence[2].getBigInteger();
    BigInteger d = sequence[3].getBigInteger();
    BigInteger p = sequence[4].getBigInteger();
    BigInteger q = sequence[5].getBigInteger();
    BigInteger d_mod_p1 = sequence[6].getBigInteger();
    BigInteger d_mod_q1 = sequence[7].getBigInteger();
    BigInteger mod_p = sequence[8].getBigInteger();

    PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(n, e, d, p, q, d_mod_p1, d_mod_q1, mod_p));
    PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));

    return new PEM(privateKey, publicKey);
  }

  @Override
  public KeyType keyType() {
    return KeyType.RSA;
  }
}
