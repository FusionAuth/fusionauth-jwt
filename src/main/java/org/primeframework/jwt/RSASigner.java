/*
 * Copyright (c) 2016, Inversoft Inc., All Rights Reserved
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

package org.primeframework.jwt;

import org.primeframework.jwt.domain.Algorithm;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Objects;

/**
 * This class can sign and verify a JWT using an RSA public / private key pair. An instance of this class is intended to be re-used with the {@link Verifier}.
 *
 * @author Daniel DeGroff
 */
public class RSASigner extends Signer {

  // RSA Private Key file (PKCS#1) End Tag
  private static final String PKCS_1_PRIVATE_KEY_END = "-----END RSA PRIVATE KEY";

  // RSA Private Key file (PKCS#1)  Start Tag
  private static final String PKCS_1_PRIVATE_KEY_START = "BEGIN RSA PRIVATE KEY-----";

  // RSA Public Key file (PKCS#1)  Start Tag
  private static final String PKCS_1_PUBLIC_KEY_START = "BEGIN RSA PUBLIC KEY-----";

  // RSA Public Key file (PKCS#1)  Start Tag
  private static final String PKCS_1_PUBLIC_KEY_END = "-----END RSA PUBLIC KEY";

  private PrivateKey privateKey;

  private PublicKey publicKey;

  public RSASigner(Algorithm algorithm) {
    super(algorithm);
  }

  private byte[] getKeyBytes(String key, String keyPrefix, String keySuffix) {
    int startIndex = key.indexOf(keyPrefix);
    int endIndex = key.indexOf(keySuffix);

    String base64 = key.substring(startIndex + keyPrefix.length(), endIndex).replaceAll("\\s", "");
    return Base64.getDecoder().decode(base64);
  }

  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  private KeySpec getRSAPrivateKeySpec(byte[] bytes) throws IOException, GeneralSecurityException {
    DerInputStream derReader = new DerInputStream(bytes);
    DerValue[] seq = derReader.getSequence(0);

    if (seq.length < 9) {
      throw new GeneralSecurityException("Could not parse a PKCS1 private key.");
    }

    // skip version seq[0];
    BigInteger modulus = seq[1].getBigInteger();
    BigInteger publicExponent = seq[2].getBigInteger();
    BigInteger privateExponent = seq[3].getBigInteger();
    BigInteger primeP = seq[4].getBigInteger();
    BigInteger primeQ = seq[5].getBigInteger();
    BigInteger primeExponentP = seq[6].getBigInteger();
    BigInteger primeExponentQ = seq[7].getBigInteger();
    BigInteger crtCoefficient = seq[8].getBigInteger();
    return new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient);
  }

  private KeySpec getRSAPublicKeySpec(byte[] bytes) throws IOException, GeneralSecurityException {
    DerInputStream derReader = new DerInputStream(bytes);
    DerValue[] seq = derReader.getSequence(0);

    if (seq.length != 2) {
      throw new GeneralSecurityException("Could not parse a PKCS1 private key.");
    }

    BigInteger modulus = seq[0].getBigInteger();
    BigInteger publicExponent = seq[1].getBigInteger();

    return new RSAPublicKeySpec(modulus, publicExponent);
  }

  public byte[] sign(String message) {
    Objects.requireNonNull(privateKey);

    try {
      Signature signature = Signature.getInstance(algorithm.algorithmName);
      signature.initSign(privateKey);
      signature.update(message.getBytes());
      return signature.sign();
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public boolean verify(String jwt) {
    Objects.requireNonNull(jwt);

    int index = jwt.lastIndexOf(".");
    byte[] message = jwt.substring(0, index).getBytes();
    byte[] jwtSignature = Base64.getUrlDecoder().decode(jwt.substring(index + 1));

    Objects.requireNonNull(publicKey);

    try {
      Signature signature = Signature.getInstance(algorithm.algorithmName);
      signature.initVerify(publicKey);
      signature.update(message);
      return signature.verify(jwtSignature);
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | SecurityException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Add a Private Key to this signer. This is required in order to call the {@link #sign(String)} method.
   *
   * @param privateKey the private key to use for signing the JWT payload.
   * @return this.
   */
  public RSASigner withPrivateKey(String privateKey) {
    try {
      byte[] bytes = getKeyBytes(privateKey, PKCS_1_PRIVATE_KEY_START, PKCS_1_PRIVATE_KEY_END);
      KeySpec keySpec = getRSAPrivateKeySpec(bytes);
      this.privateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);
      return this;
    } catch (GeneralSecurityException | IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Add a Public Key to this signer. This is required in order to call the {@link #verify(String)} method.
   *
   * @param publicKey the public key to use for verifying the JWT payload.
   * @return this.
   */
  public RSASigner withPublicKey(String publicKey) {
    try {
      byte[] bytes = getKeyBytes(publicKey, PKCS_1_PUBLIC_KEY_START, PKCS_1_PUBLIC_KEY_END);
      KeySpec keySpec = getRSAPublicKeySpec(bytes);
      this.publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);
    } catch (GeneralSecurityException | IOException e) {
      throw new RuntimeException(e);
    }

    return this;
  }
}
