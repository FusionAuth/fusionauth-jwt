/*
 * Copyright (c) 2020, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwks;

import com.fasterxml.jackson.databind.JsonNode;
import io.fusionauth.http.AbstractHttpHelper;
import io.fusionauth.jwks.domain.JSONWebKey;
import io.fusionauth.jwt.json.Mapper;

import java.net.HttpURLConnection;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * @author Daniel DeGroff
 */
public class JSONWebKeySetHelper extends AbstractHttpHelper {
  /**
   * Retrieve a list of JSON Web Keys from the JWK endpoint using the OIDC issuer as a starting point.
   *
   * @param issuer the OIDC issuer used to resolve the OpenID Connect discovery document which will be used to resolve the JWKS endpoint.
   * @return a list of keys or an empty set if no keys were found at the endpoint.
   */
  public static List<JSONWebKey> retrieveKeysFromIssuer(String issuer) {
    return retrieveKeysFromIssuer(issuer, null);
  }

  /**
   * Retrieve a list of JSON Web Keys from the JWK endpoint using the OIDC issuer as a starting point.
   *
   * @param issuer   the OIDC issuer used to resolve the OpenID Connect discovery document which will be used to resolve the JWKS endpoint.
   * @param consumer an optional consumer to modify the HTTP URL Connection before making the request.
   * @return a list of keys or an empty set if no keys were found at the endpoint.
   */
  public static List<JSONWebKey> retrieveKeysFromIssuer(String issuer, Consumer<HttpURLConnection> consumer) {
    Objects.requireNonNull(issuer);
    if (issuer.endsWith("/")) {
      issuer = issuer.substring(0, issuer.length() - 1);
    }

    return retrieveKeysFromWellKnownConfiguration(issuer + "/.well-known/openid-configuration", consumer);
  }

  /**
   * Retrieve JSON Web Keys from an OpenID Connect well known discovery endpoint. Use this method if you want to resolve the JWKS endpoint from the OpenID Connect discovery document and you want to build your own HTTP URL Connection.
   *
   * @param httpURLConnection the HTTP URL Connection that will be used to connect to the discovery endpoint used to resolve the JWKS endpoint.
   * @return a list of JSON Web Keys
   */
  public static List<JSONWebKey> retrieveKeysFromWellKnownConfiguration(HttpURLConnection httpURLConnection) {
    return get(httpURLConnection,
        is -> {
          JsonNode response = Mapper.deserialize(is, JsonNode.class);
          JsonNode jwksURI = response.at("/jwks_uri");
          if (jwksURI.isMissingNode()) {
            String endpoint = httpURLConnection.getURL().toString();
            throw new JSONWebKeySetException("The well-known endpoint [" + endpoint + "] has not defined a JSON Web Key Set endpoint. Missing the [jwks_uri] property.");
          }

          return retrieveKeysFromJWKS(jwksURI.asText());
        },
        JSONWebKeyBuilderException::new);
  }

  /**
   * Retrieve JSON Web Keys from an OpenID Connect well known discovery endpoint. Use this method if you want to resolve the JWKS endpoint from the OpenID Connect discovery document.
   *
   * @param endpoint the OpenID Connect well known discovery endpoint used to resolve the JWKS endpoint.
   * @return a list of JSON Web Keys
   */
  public static List<JSONWebKey> retrieveKeysFromWellKnownConfiguration(String endpoint) {
    return retrieveKeysFromWellKnownConfiguration(endpoint, null);
  }

  /**
   * Retrieve JSON Web Keys from an OpenID Connect well known discovery endpoint. Use this method if you want to resolve the JWKS endpoint from the OpenID Connect discovery document.
   *
   * @param endpoint the OpenID Connect well known discovery endpoint used to resolve the JWKS endpoint.
   * @param consumer an optional consumer to modify the HTTP URL Connection before making the request.
   * @return a list of JSON Web Keys
   */
  public static List<JSONWebKey> retrieveKeysFromWellKnownConfiguration(String endpoint, Consumer<HttpURLConnection> consumer) {
    HttpURLConnection connection = buildURLConnection(endpoint);
    if (consumer != null) {
      consumer.accept(connection);
    }

    return retrieveKeysFromWellKnownConfiguration(connection);
  }

  /**
   * Retrieve JSON Web Keys from a JSON Web Key Set (JWKS) endpoint. Use this method if you know the specific JWKS URL.
   *
   * @param endpoint the JWKS endpoint.
   * @return a list of JSON Web Keys
   */
  public static List<JSONWebKey> retrieveKeysFromJWKS(String endpoint) {
    return retrieveKeysFromJWKS(endpoint, null);
  }

  /**
   * Retrieve JSON Web Keys from a JSON Web Key Set (JWKS) endpoint. Use this method if you know the specific JWKS URL.
   *
   * @param endpoint the JWKS endpoint.
   * @param consumer an optional consumer to modify the HTTP URL Connection before making the request.
   * @return a list of JSON Web Keys
   */
  public static List<JSONWebKey> retrieveKeysFromJWKS(String endpoint, Consumer<HttpURLConnection> consumer) {
    HttpURLConnection connection = buildURLConnection(endpoint);
    if (consumer != null) {
      consumer.accept(connection);
    }

    return retrieveKeysFromJWKS(connection);
  }

  /**
   * Retrieve JSON Web Keys from a JSON Web Key Set (JWKS) endpoint. Use this method if you know the specific JWKS URL and you want to build your own HTTP URL Connection.
   *
   * @param httpURLConnection the URL connection that will be used to connect to the JWKS endpoint.
   * @return a list of JSON Web Keys
   */
  public static List<JSONWebKey> retrieveKeysFromJWKS(HttpURLConnection httpURLConnection) {
    return get(
        httpURLConnection,
        is -> Mapper.deserialize(is, JSONWebKeySetResponse.class).keys,
        JSONWebKeyBuilderException::new);
  }

  public static class JSONWebKeySetException extends RuntimeException {
    public JSONWebKeySetException(String message) {
      super(message);
    }

    public JSONWebKeySetException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  // Note, with the introduction of the Java Platform Module System (JPMS), private classes are no longer visible via
  // reflection. To ensure Jackson can de-serialize this class, it must be public.
  public static class JSONWebKeySetResponse {
    public List<JSONWebKey> keys;
  }
}
