package io.fusionauth.security;

import io.fusionauth.jwt.domain.Algorithm;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.testng.annotations.Test;

import javax.crypto.Mac;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;

/**
 * A playground for Bouncy Castle testing (mostly for FIPS).
 *
 * @author Brian Pontarelli
 */
public class BouncyCastleProviderTest {
  static {
    System.setProperty("org.bouncycastle.fips.approved_only", "true");
  }

  @Test(enabled = false)
  public void jca() {
    Security.insertProviderAt(new BouncyCastleFipsProvider(), 1);

    for (Algorithm algorithm : Algorithm.values()) {
      try {
        Mac mac = Mac.getInstance(algorithm.getName());
//        System.out.println(mac.getClass());
        System.out.println("For algo [" + algorithm.getName() + "] " + mac.getProvider().getClass());
//        System.out.println();
      } catch (NoSuchAlgorithmException e) {
        System.out.println("Missing mac algo [" + algorithm.getName() + "]");
      }
    }

    for (Algorithm algorithm : Algorithm.values()) {
      try {
        Signature signature = Signature.getInstance(algorithm.getName());
//        System.out.println(signature.getClass());
        System.out.println("For algo [" + algorithm.getName() + "] " + signature.getProvider().getClass());
//        System.out.println();
      } catch (NoSuchAlgorithmException e) {
        System.out.println("Missing signature algo [" + algorithm.getName() + "]");
      }
    }

    try {
      MessageDigest md = MessageDigest.getInstance("SHA-512");
      System.out.println("For algo [SHA-512] " + md.getClass() + " " + md.getProvider());
    } catch (NoSuchAlgorithmException e) {
      System.out.println(e);
    }

    try {
      MessageDigest md = MessageDigest.getInstance("MD5");
      System.out.println("For algo [MD5] " + md.getClass() + " " + md.getProvider());
    } catch (NoSuchAlgorithmException e) {
      System.out.println(e);
    }
  }
}
