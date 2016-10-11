package org.primeframework.jwt.domain;

/**
 * @author Daniel DeGroff
 */
public class InvalidKeyLengthException extends RuntimeException {
  public InvalidKeyLengthException(String message) {
    super(message);
  }
}
