package org.primeframework.jwt;

/**
 * Unsecured signer.
 *
 * @author Daniel DeGroff
 */
public class UnsecuredSigned extends Signer {
  public UnsecuredSigned() {
    super();
  }

  @Override
  byte[] sign(String message) {
    return new byte[0];
  }

  @Override
  boolean verify(String jwt) {
    return true;
  }
}
