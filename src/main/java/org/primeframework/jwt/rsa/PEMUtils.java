package org.primeframework.jwt.rsa;

/**
 * @author Daniel DeGroff
 */
public class PEMUtils {
  // PEM Encoded Certificate  Start Tag
  public static final String CERTIFICATE_PREFIX = "-----BEGIN CERTIFICATE-----";

  // PEM Encoded Certificate End Tag
  public static final String CERTIFICATE_SUFFIX = "-----END CERTIFICATE-----";

  // PEM Encoded RSA Private Key file (PKCS#1)  Start Tag
  public static final String PKCS_1_PRIVATE_KEY_PREFIX = "-----BEGIN RSA PRIVATE KEY-----";

  // PEM Encoded RSA Private Key file (PKCS#1) End Tag
  public static final String PKCS_1_PRIVATE_KEY_SUFFIX = "-----END RSA PRIVATE KEY-----";

  // RSA Public Key file (PKCS#1)  Start Tag
  public static final String PKCS_1_PUBLIC_KEY_PREFIX = "-----BEGIN RSA PUBLIC KEY-----";

  // RSA Public Key file (PKCS#1)  End Tag
  public static final String PKCS_1_PUBLIC_KEY_SUFFIX = "-----END RSA PUBLIC KEY-----";

  // PEM Encoded RSA Private Key file (PKCS#8)  Start Tag
  public static final String PKCS_8_PRIVATE_KEY_PREFIX = "-----BEGIN PRIVATE KEY-----";

  // PEM Encoded RSA Private Key file (PKCS#8)  End Tag
  public static final String PKCS_8_PRIVATE_KEY_SUFFIX = "-----END PRIVATE KEY-----";

  // PEM Encoded RSA Public Key file (X.509)  Start Tag
  public static final String PKCS_8_X509_PUBLIC_KEY_PREFIX = "-----BEGIN PUBLIC KEY-----";

  // PEM Encoded RSA Public Key file (X.509)  End Tag
  public static final String PKCS_8_X509_PUBLIC_KEY_SUFFIX = "-----END PUBLIC KEY-----";
}
