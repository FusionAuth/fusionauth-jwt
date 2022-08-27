/*
 * Copyright (c) 2020-2022, FusionAuth, All Rights Reserved
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

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.time.ZonedDateTime;
import java.util.Date;

import io.fusionauth.der.DerOutputStream;
import io.fusionauth.der.DerValue;
import io.fusionauth.der.Tag;

/**
 * @author Daniel DeGroff
 */
public class KeyUtils {

  public static X509Certificate generateX509CertificateFromKey(String id, String algorithm, ZonedDateTime insertInstant, String issuer, PublicKey publicKey, PrivateKey privateKey) {
    /**
     * Example Elliptic Curve Certificate - ECDSA using P-256 and SHA-256
     *
     * SEQUENCE (3 elem)
     *   SEQUENCE (7 elem)
     *     [0] (1 elem)
     *       INTEGER 1
     *     INTEGER (126 bit) 62010065869171989962325313903404886146
     *     SEQUENCE (2 elem)
     *       OBJECT IDENTIFIER 1.2.840.10045.4.3.2 ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
     *       NULL
     *     SEQUENCE (1 elem)
     *       SET (1 elem)
     *         SEQUENCE (2 elem)
     *           OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
     *           PrintableString acme.com
     *     SEQUENCE (2 elem)
     *       UTCTime 2019-04-23 06:01:48 UTC
     *       UTCTime 2029-04-23 06:01:48 UTC
     *     SEQUENCE (1 elem)
     *       SET (1 elem)
     *         SEQUENCE (2 elem)
     *           OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
     *           PrintableString acme.com
     *     SEQUENCE (2 elem)
     *       SEQUENCE (2 elem)
     *         OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
     *         OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1 (ANSI X9.62 named elliptic curve)
     *       BIT STRING (520 bit) 0000010000111101000010011010111010000111001000000000110110111100101001…
     *   SEQUENCE (2 elem)
     *     OBJECT IDENTIFIER 1.2.840.10045.4.3.2 ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
     *     NULL
     *   BIT STRING (1 elem)
     *     SEQUENCE (2 elem)
     *       INTEGER (255 bit) 3677564850171735423403673002135940436205659525125431104742130770335500…
     *       INTEGER (252 bit) 4861705725831092640833585301304199200675190489357124256265667422002978…
     */

    // Sequence
    //
    //   - Sequence (7)
    //     - [0]
    //
    //     - Integer
    //
    //     - Sequence (2)
    //        - Object Identifier (1.2.840.10045.4.3.2 ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
    //        - Null
    //
    //     - Sequence (1)
    //        - Set (1)
    //             - Sequence (2)
    //                  - Object Identifier (2.5.4.3 - X.520 DN)
    //                  - PrintableString (acme.com) -- This is the Subject or Issuer CN?
    //
    //     - Sequence (2)
    //        - UTCTime (valid from)
    //        - UTCTime (valid to)
    //
    //     - Sequence (1)
    //        - Set (1)
    //             - Sequence (2)
    //                  - Object Identifier (2.5.4.3 - X.520 DN)
    //                  - PrintableString (acme.com) -- This is the Subject or Issuer CN?
    //     - Sequence (2)
    //        - Sequence (2)
    //             - Object Identifier (1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
    //             - Object Identifier (1.2.840.10045.3.1.7 prime256v1 (ANSI X9.62 named elliptic curve)
    //        - Bit String (520 bit)
    //
    //   - Sequence
    //        - Object Identifier (1.2.840.10045.4.3.2 ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256))
    //        - Null
    //
    //   - Bit String (1)
    //        - Sequence (2)
    //           - Integer (255 bit) - I think this is the public key - modulus or exponent?
    //           - Integer (252 bit) - I think this is the public key - modulus or exponent?
    //


//    // Build an X.509 DER encoded byte array from the provided bitString
//    //
//    // SubjectPublicKeyInfo ::= SEQUENCE {
//    //   algorithm         AlgorithmIdentifier,
//    //   subjectPublicKey  BIT STRING
//    // }
//    DerValue[] sequence = new DerInputStream(privateKey.getEncoded()).getSequence();
//    byte[] encodedPublicKey = new DerOutputStream()
//        .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
//            .writeValue(new DerValue(Tag.Sequence, sequence[1].toByteArray()))
//            .writeValue(new DerValue(Tag.BitString, bitString.toByteArray()))))
//        .toByteArray();

    // 0x30
    // 0x82
    // 0x02

    // Currently only supporting RSA or ECDSA
//    byte[] encryptionOID = privateKey.getAlgorithm().equals("RSA") ? RSA_ENCRYPTION_OID : EC_ENCRYPTION_OID;

    byte[] algorithmOID = toObjectIdentifier(algorithm);

    Date notBefore = Date.from(insertInstant.toInstant());
    Date notAfter = Date.from(insertInstant.plusYears(10).toInstant());

    final long YR_2050 = 2524608000000L;
    DerValue notBeforeDerValue = (notBefore.getTime() < YR_2050) ? DerValue.newUTCTime(notBefore) : DerValue.newGeneralizedTime(notBefore);
    DerValue notAfterDerValue = (notAfter.getTime() < YR_2050) ? DerValue.newUTCTime(notAfter) : DerValue.newGeneralizedTime(notAfter);

//    certInfo.set(X509CertInfo.VALIDITY, new CertificateValidity(Date.from(key.insertInstant.toInstant()), Date.from(key.insertInstant.plusYears(10).toInstant())));


    try {
      DerOutputStream outputStream = new DerOutputStream()
          // 1st Element
          .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
              // [0] : Constructed Context Specific : Version 2
              .writeValue(new DerValue(new Tag(0b10100000), new DerOutputStream().writeValue(new DerValue(BigInteger.valueOf(1)))))
              // [1] : Integer : Serial Number
              .writeValue(new DerValue(new BigInteger(id.replace("-", ""), 16)))
              // [2] : Sequence : Signature Algorithm Object Identifier
              //                         --> Algorithm OID
              //                         --> NULL
              .writeValue(new DerValue(Tag.Sequence, new DerOutputStream().writeValue(new DerValue(Tag.ObjectIdentifier, algorithmOID))
                  .writeValue(DerValue.newNull())))

              // [3] : Sequence
              .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()

                  // [0] 2.5.4.3 commonName (X.520 DN component)
                  .writeValue(new DerValue(Tag.Set, new DerOutputStream()
                      // 2.5.4.3
                      .writeValue(new DerValue(Tag.Sequence, new DerOutputStream().writeValue(new DerValue(Tag.ObjectIdentifier, new byte[]{(byte) 0x55, (byte) 0x04, (byte) 0x03}))
                          .writeValue(DerValue.newASCIIString(issuer))
                      ))
                  ))
              ))

              // [4] : Sequence -> Validity to and From using UTCTime tag (0x17)
              //                         [0] notBefore
              //                         [1] notAfter
              .writeValue(new DerValue(Tag.Sequence, new DerOutputStream().writeValue(notBeforeDerValue)
                  .writeValue(notAfterDerValue)))

              // [5] : Set -> Sequence -> [0] -> [OID, OID]
              //                       -> [1] - > Bit String
              // Set : Sequence : [0] OID : 2.5.4.3 'commonName'
              //                  [1] PrintableString
              // commonName (X.520 DN component)
              .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
                  .writeValue(new DerValue(Tag.Set, new DerOutputStream()
                      .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
                          .writeValue(new DerValue(Tag.ObjectIdentifier, new byte[]{(byte) 0x55, (byte) 0x04, (byte) 0x03}))
                          .writeValue(DerValue.newASCIIString(issuer))
                      ))
                  ))
              ))

              // public key
              .writeValue(publicKey.getEncoded())
          ))

          .writeValue(new DerValue(Tag.Sequence, new DerOutputStream().writeValue(new DerValue(Tag.ObjectIdentifier, algorithmOID))
              .writeValue(DerValue.newNull()))
          );

//      X509CertImpl impl = new X509CertImpl(certInfo);
//      PrivateKey privateKey = PEM.decode(key.privateKey).privateKey;
//      impl.sign(privateKey, key.algorithm.algorithm);
//      return impl;


      // TODO : FIPS : Need to optionally use a BCFIPS provider?
      CertificateFactory cf = CertificateFactory.getInstance("X.509");

      byte[] rawCertInfo = outputStream.toByteArray();

      // TODO : Hard coded, need to pass it in
      @SuppressWarnings("scwbasic-protection-set_CryptoSignatureInsecureHashingAlgorithm")
      Signature signer = Signature.getInstance("SHA256withRSA");
      signer.initSign(privateKey);
      signer.update(rawCertInfo, 0, rawCertInfo.length);
      byte[] signature = signer.sign();

      // Append the signature.
      outputStream.writeValue(DerValue.newBitString(signature));

      // Build a container using a sequence around the cert info
      DerOutputStream container = new DerOutputStream().writeValue(new DerValue(Tag.Sequence, outputStream));
      return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(container.toByteArray()));


    } catch (Exception e) {
      System.out.println("Whoops");
      System.out.println(e);
    }

    /*
     *
     * TBSCertificate  ::=  SEQUENCE  {
     *     version         [0]  EXPLICIT Version DEFAULT v1,
     *     serialNumber         CertificateSerialNumber,
     *     signature            AlgorithmIdentifier,
     *     issuer               Name,
     *     validity             Validity,
     *     subject              Name,
     *     subjectPublicKeyInfo SubjectPublicKeyInfo,
     *     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                          -- If present, version must be v2 or v3
     *     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                          -- If present, version must be v2 or v3
     *     extensions      [3]  EXPLICIT Extensions OPTIONAL
     *                          -- If present, version must be v3
     *     }
     *
     *  Validity ::= SEQUENCE {
     *     notBefore      CertificateValidityDate,
     *     notAfter       CertificateValidityDate
     *  }
     *
     *  CertificateValidityDate ::= CHOICE {
     *     utcTime        UTCTime,
     *     generalTime    GeneralizedTime
     *  }
     *
     */

    return null;
  }
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

      // If bytes is not a multiple of 8, add the difference to get to the next 8 byte boundary
      int mod = bytes % 8;
      // Adjust the length for a mod count of anything equal to or greater than 2.
      if (mod >= 2) {
        bytes = bytes + (8 - mod);
      }

      return ((bytes / 8) * 8) * 8;
    } else if (key instanceof RSAKey) {
      return ((RSAKey) key).getModulus().bitLength();
    }

    throw new IllegalArgumentException();
  }
  private static byte[] bytes(int... bees) {
    byte[] result = new byte[bees.length];
    for (int i = 0; i < bees.length; i++) {
      result[i] = (byte) bees[i];
    }
    return result;
  }

  private static byte[] toObjectIdentifier(String algorithm) {
    // EC
    // 1.2.840.10045.2
    // 06 06 2A 86 48 CE 3D 02
    //

    // RSA
    // 1.2.840.113549.1.1.1
    // 06 09 2A 86 48 86 F7 0D 01 01 01

    switch (algorithm) {
      case "ES256":
        // 1.2.840.10045.4.3.2
        // 06 08 2A 86 48 CE 3D 04 03 02
//        return AlgorithmId.sha256WithECDSA_oid;
        return new byte[]{(byte) 0x06, (byte) 0x08, (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xCE, (byte) 0x3D, (byte) 0x04, (byte) 0x03, (byte) 0x02};
      case "ES384":
        // 1.2.840.10045.4.3.3
        // 06 08 2A 86 48 CE 3D 04 03 03
//        return AlgorithmId.sha384WithECDSA_oid;
        return new byte[]{(byte) 0x06, (byte) 0x08, (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xCE, (byte) 0x3D, (byte) 0x04, (byte) 0x03, (byte) 0x03};
      case "ES512":
        // 1.2.840.10045.4.3.4
        // 06 08 2A 86 48 CE 3D 04 03 04
//        return AlgorithmId.sha512WithECDSA_oid;
        return new byte[]{(byte) 0x06, (byte) 0x08, (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xCE, (byte) 0x3D, (byte) 0x04, (byte) 0x03, (byte) 0x04};

      case "RS256":
        // 1.2.840.113549.1.1.11
        return bytes(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B);

      case "RS384":
        // 1.2.840.113549.1.1.12
        return bytes(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C);

      case "RS512":
        // 1.2.840.113549.1.1.13
        return bytes(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D);

      default:
        throw new IllegalArgumentException("Invalid algorithm [" + algorithm + "].");
    }
  }
}
