package io.fusionauth.jwks;

import io.fusionauth.jwks.domain.JSONWebKey;
import org.testng.annotations.Test;

import java.util.List;

import static org.testng.Assert.assertEquals;

/**
 * @author Daniel DeGroff
 */
public class JSONWebKeySetTest {
  @Test
  public void test() {
    // Retrieve keys using the issuer, well known openid-configuration endpoint and well known JWKS endpoint, all should be equal.
    List<JSONWebKey> keys1 = JSONWebKeySetHelper.retrieveKeysFromIssuer("https://accounts.google.com");
    List<JSONWebKey> keys2 = JSONWebKeySetHelper.retrieveKeysFromWellKnownConfiguration("https://accounts.google.com/.well-known/openid-configuration");
    List<JSONWebKey> keys3 = JSONWebKeySetHelper.retrieveKeysFromJWKS("https://www.googleapis.com/oauth2/v3/certs");
    assertEquals(keys1, keys2);
    assertEquals(keys2, keys3);
  }
}
