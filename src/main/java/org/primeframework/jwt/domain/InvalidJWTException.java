package org.primeframework.jwt.domain;

/**
 * The JWT could not be parsed properly. It does not conform to the JWT specification.
 *
 * @author Daniel DeGroff
 */
public class InvalidJWTException extends Exception {
  public InvalidJWTException(String message) {
    super(message);
  }

  public InvalidJWTException(String message, Throwable cause) {
    super(message, cause);
  }
}
