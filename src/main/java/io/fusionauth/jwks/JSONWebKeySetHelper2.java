package io.fusionauth.jwks;

import tools.jackson.databind.JsonNode;
import io.fusionauth.http.AbstractHttpHelper2;
import io.fusionauth.jwks.domain.JSONWebKey;
import io.fusionauth.jwt.json.Mapper;

import java.net.http.HttpRequest;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * @author Daniel DeGroff
 */
public class JSONWebKeySetHelper2 extends AbstractHttpHelper2 {

  public static List<JSONWebKey> retrieveKeysFromIssuer(String issuer) {
    return retrieveKeysFromIssuer(issuer, null);
  }

  public static List<JSONWebKey> retrieveKeysFromIssuer(String issuer, Consumer<HttpRequest.Builder> consumer) {
    Objects.requireNonNull(issuer);
    if (issuer.endsWith("/")) {
      issuer = issuer.substring(0, issuer.length() - 1);
    }
    return retrieveKeysFromWellKnownConfiguration(issuer + "/.well-known/openid-configuration", consumer);
  }

  public static List<JSONWebKey> retrieveKeysFromWellKnownConfiguration(String endpoint) {
    return retrieveKeysFromWellKnownConfiguration(endpoint, null);
  }

  public static List<JSONWebKey> retrieveKeysFromWellKnownConfiguration(String endpoint, Consumer<HttpRequest.Builder> consumer) {
    HttpRequest request = buildRequest(endpoint, consumer);
    return get(request,
        is -> {
          JsonNode response = Mapper.deserialize(is, JsonNode.class);
          JsonNode jwksURI = response.at("/jwks_uri");
          if (jwksURI.isMissingNode()) {
            throw new JSONWebKeySetException(
                "The well-known endpoint [" + endpoint + "] has not defined a JSON Web Key Set endpoint. Missing the [jwks_uri] property.");
          }
          return retrieveKeysFromJWKS(jwksURI.asString(), consumer);
        },
        JSONWebKeySetException::new);
  }

  public static List<JSONWebKey> retrieveKeysFromJWKS(String endpoint) {
    return retrieveKeysFromJWKS(endpoint, null);
  }

  public static List<JSONWebKey> retrieveKeysFromJWKS(String endpoint, Consumer<HttpRequest.Builder> consumer) {
    HttpRequest request = buildRequest(endpoint, consumer);
    return get(
        request,
        is -> Mapper.deserialize(is, JSONWebKeySetResponse.class).keys,
        JSONWebKeySetException::new);
  }

  public static class JSONWebKeySetException extends RuntimeException {

	private static final long serialVersionUID = -7684778018760585593L;

	public JSONWebKeySetException(String message) {
      super(message);
    }

    public JSONWebKeySetException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  public static class JSONWebKeySetResponse {
    public List<JSONWebKey> keys;
  }
}