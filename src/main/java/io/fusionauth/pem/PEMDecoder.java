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

package io.fusionauth.pem;

import io.fusionauth.der.DerDecodingException;
import io.fusionauth.der.DerInputStream;
import io.fusionauth.der.DerOutputStream;
import io.fusionauth.der.DerValue;
import io.fusionauth.der.ObjectIdentifier;
import io.fusionauth.der.Tag;
import io.fusionauth.jwt.domain.KeyType;
import io.fusionauth.pem.domain.PEM;

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
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import static io.fusionauth.pem.domain.PEM.EC_PRIVATE_KEY_PREFIX;
import static io.fusionauth.pem.domain.PEM.EC_PRIVATE_KEY_SUFFIX;
import static io.fusionauth.pem.domain.PEM.PKCS_1_PRIVATE_KEY_PREFIX;
import static io.fusionauth.pem.domain.PEM.PKCS_1_PRIVATE_KEY_SUFFIX;
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
  private static final byte[] EC_ENCRYPTION_OID = new byte[]{(byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xCE, (byte) 0x3D, (byte) 0x02, (byte) 0x01};

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
      throw new PEMDecoderException("Unable to read the file from path [" + path.toAbsolutePath().toString() + "]", e);
    }
  }

  /**
   * Decode a PEM and extract the public or private keys. If the encoded private key contains the public key, the returned
   * PEM object will contain both keys.
   *
   * @param bytes the byte array of the the encoded PEM file
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
   * @param encodedKey the string representation the the encoded PEM
   * @return a PEM object containing a public or private key, or both
   */
  public PEM decode(String encodedKey) {
    Objects.requireNonNull(encodedKey);

    try {
      if (encodedKey.contains(PKCS_1_PUBLIC_KEY_PREFIX)) {
        return decode_PKCS_1_Public(encodedKey);
      } else if (encodedKey.contains(X509_PUBLIC_KEY_PREFIX)) {
        return decode_X_509(encodedKey);
      } else if (encodedKey.contains(X509_CERTIFICATE_PREFIX)) {
        return decode_certificate(encodedKey);
      } else if (encodedKey.contains(PKCS_1_PRIVATE_KEY_PREFIX)) {
        return decode_PKCS_1_Private(encodedKey);
      } else if (encodedKey.contains(PKCS_8_PRIVATE_KEY_PREFIX)) {
        return decode_PKCS_8(encodedKey);
      } else if (encodedKey.contains(EC_PRIVATE_KEY_SUFFIX)) {
        return decode_EC_privateKey(encodedKey);
      } else {
        throw new PEMDecoderException(new InvalidParameterException("Unexpected PEM Format"));
      }
    } catch (CertificateException | InvalidKeyException | InvalidKeySpecException | IOException | NoSuchAlgorithmException e) {
      throw new PEMDecoderException(e);
    }
  }

  private PEM decode_EC_privateKey(String encodedKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] bytes = getKeyBytes(encodedKey, EC_PRIVATE_KEY_PREFIX, EC_PRIVATE_KEY_SUFFIX);
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

    ECPrivateKey privateKey = (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs_8.toByteArray()));

    // Extract the public key from the PEM
    DerValue bitString = new DerInputStream(sequence[3]).readDerValue();
    PublicKey publicKey = getPublicKeyFromPrivateEC(bitString, privateKey);

    // The publicKey may be null if it was not found in the private key
    return new PEM(privateKey, publicKey);
  }

  private PEM decode_PKCS_1_Private(String encodedKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] bytes = getKeyBytes(encodedKey, PKCS_1_PRIVATE_KEY_PREFIX, PKCS_1_PRIVATE_KEY_SUFFIX);
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

    if (sequence.length != 3 || !sequence[0].tag.is(Tag.Integer) || !sequence[1].tag.is(Tag.Sequence) || !sequence[2].tag.is(Tag.OctetString)) {
      // Expect the following format : [ Integer | Sequence | OctetString ]
      throw new InvalidKeyException("Could not decode the private key. Expecting values in the DER encoded sequence in the following format [ Integer | Sequence | OctetString ]");
    }

    ObjectIdentifier algorithmOID = new DerInputStream(sequence[1].toByteArray()).getOID();
    KeyType type = KeyType.getKeyTypeFromOid(algorithmOID.decode());
    if (type == null) {
      throw new InvalidKeyException("Could not decode the private key. Expected an EC or RSA key type but found OID [" + algorithmOID.decode() + "] and was unable to match that to a supported algorithm.");
    }

    @SuppressWarnings("scwbasic-protection-set_DataProtection-CryptographyAvoidcryptographicweaknessUseappropriatekeypairgenerationalgorithmnotrecommended")
    PrivateKey privateKey = KeyFactory.getInstance(type.name()).generatePrivate(new PKCS8EncodedKeySpec(bytes));

    // Attempt to extract the public key if available
    if (privateKey instanceof ECPrivateKey) {
      DerValue[] privateKeySequence = new DerInputStream(sequence[2]).getSequence();
      if (privateKeySequence.length == 3 && privateKeySequence[2].tag.rawByte == (byte) 0xA1) {
        DerValue bitString = new DerInputStream(privateKeySequence[2]).readDerValue();
        PublicKey publicKey = getPublicKeyFromPrivateEC(bitString, (ECPrivateKey) privateKey);
        return new PEM(privateKey, publicKey);
      } else {
        // The private key did not contain the public key
        return new PEM(privateKey);
      }
    } else if (privateKey instanceof RSAPrivateCrtKey) {
      BigInteger modulus = ((RSAPrivateCrtKey) privateKey).getModulus();
      BigInteger publicExponent = ((RSAPrivateCrtKey) privateKey).getPublicExponent();
      PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
      return new PEM(privateKey, publicKey);
    }

    return new PEM(privateKey);
  }

  private PEM decode_certificate(String encodedKey) throws CertificateException, DerDecodingException, NoSuchAlgorithmException {
    // The certificate is the easy part. Let's see if this also includes a private key.
    PEM pem = new PEM(CertificateFactory.getInstance("X.509").generateCertificate(
        new ByteArrayInputStream(getKeyBytes(encodedKey, X509_CERTIFICATE_PREFIX, X509_CERTIFICATE_SUFFIX))));

    try {
      byte[] bytes = getKeyBytes(encodedKey, X509_CERTIFICATE_PREFIX, X509_CERTIFICATE_SUFFIX);
      DerValue[] sequence = new DerInputStream(bytes).getSequence();

      if (sequence.length == 3 && sequence[2].tag.is(Tag.BitString)) {
//        DerValue algorithm = new DerInputStream(sequence[1].toByteArray()).readDerValue();
        byte[] actual = sequence[2].toByteArray();
        if (actual[0] == 0) {
          actual = Arrays.copyOfRange(actual, 1, actual.length);
        }

        byte[] derBytes = new DerValue(Tag.Sequence, sequence[2].toByteArray()).getBitStringBytes();
        DerValue[] privateKeySequence = new DerInputStream(derBytes).getSequence();

//        BigInteger exp = new BigInteger(Arrays.copyOfRange(actual, 0, 4));
//        BigInteger mod = new BigInteger(Arrays.copyOfRange(actual, 4, actual.length));
//        RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(mod, exp);
//        RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(keySpec);
//        DerValue bitString = new DerValue(Tag.Sequence, actual);
//
//        DerValue seq2 = new DerInputStream(bitString).readDerValue();
//
//        ECPrivateKey privateKey = (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(sequence[2].toByteArray()));
//        pem.privateKey = privateKey;

//        pem.privateKey = privateKey;


        System.out.println("here");
//        new DerInputStream(sequence[3]).readDerValue()
//        System.out.println(string);
//        DerValue[] privateKeySequence = new DerInputStream(sequence[2]).getSequence();

        // AlgorithmIdentifier ::= SEQUENCE {
        //   algorithm       OBJECT IDENTIFIER,
        //   parameters      ANY DEFINED BY algorithm OPTIONAL
        // }

        // RSAPrivateKey     OCTET STRING

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


//        if (privateKeySequence.length < 9) {
//          throw new PEMDecoderException(
//              new InvalidKeyException("Could not build a PKCS#1 private key. Expected at least 9 values in the DER encoded sequence."));
//        }

//        // Ignoring the version value in the sequence
//        BigInteger n = sequence[1].getBigInteger();
//        BigInteger e = sequence[2].getBigInteger();
//        BigInteger d = sequence[3].getBigInteger();
//        BigInteger p = sequence[4].getBigInteger();
//        BigInteger q = sequence[5].getBigInteger();
//        BigInteger d_mod_p1 = sequence[6].getBigInteger();
//        BigInteger d_mod_q1 = sequence[7].getBigInteger();
//        BigInteger mod_p = sequence[8].getBigInteger();
//
//        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(n, e, d, p, q, d_mod_p1, d_mod_q1, mod_p));
//        pem.privateKey = privateKey;
      }

    } catch (Exception e) {
      System.out.println(e.getMessage());
    }


    return null;
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

    KeyType type = KeyType.getKeyTypeFromOid(algorithmOID.decode());
    if (type == null) {
      throw new InvalidKeyException("Could not decode the X.509 public key. Expected at 2 values in the DER encoded sequence but found [" + sequence.length + "]");
    }

    //noinspection scwbasic-protection-set_DataProtection-CryptographyAvoidcryptographicweaknessUseappropriatekeypairgenerationalgorithmnotrecommended
    return new PEM(KeyFactory.getInstance(type.name()).generatePublic(new X509EncodedKeySpec(bytes)));
  }

  private byte[] getKeyBytes(String key, String keyPrefix, String keySuffix) {
    int startIndex = key.indexOf(keyPrefix);
    int endIndex = key.indexOf(keySuffix);

    String base64 = key.substring(startIndex + keyPrefix.length(), endIndex).replaceAll("\\s+", "");
    return Base64.getDecoder().decode(base64);
  }

  private PublicKey getPublicKeyFromPrivateEC(DerValue bitString, ECPrivateKey privateKey) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException {
    // Build an X.509 DER encoded byte array from the provided bitString
    //
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm         AlgorithmIdentifier,
    //   subjectPublicKey  BIT STRING
    // }
    DerValue[] sequence = new DerInputStream(privateKey.getEncoded()).getSequence();
    byte[] encodedPublicKey = new DerOutputStream()
        .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
            .writeValue(new DerValue(Tag.Sequence, sequence[1].toByteArray()))
            .writeValue(new DerValue(Tag.BitString, bitString.toByteArray()))))
        .toByteArray();

    return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(encodedPublicKey));
  }
}
