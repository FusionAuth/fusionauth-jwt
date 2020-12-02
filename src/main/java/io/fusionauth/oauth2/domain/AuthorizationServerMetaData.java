package io.fusionauth.oauth2.domain;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import io.fusionauth.jwt.json.Mapper;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Server Metadata as defined by <a href="https://tools.ietf.org/html/rfc8414">RFC 8414</a>
 *
 * @author Daniel DeGroff
 */
public class AuthorizationServerMetaData {
  public String authorization_endpoint;

  public List<String> code_challenge_methods_supported;

  public List<String> grant_types_supported;

  public String introspection_endpoint;

  public List<String> introspection_endpoint_auth_methods_supported;

  public List<String> introspection_endpoint_auth_signing_alg_values_supported;

  public String issuer;

  public String jwks_uri;

  public String op_policy_uri;

  public String op_tos_uri;

  /**
   * This Map will contain all the claims that aren't specifically defined in the specification. These still might be
   * IANA registered claims, but are not known JWT specification claims.
   */
  @JsonAnySetter
  public Map<String, Object> otherClaims = new LinkedHashMap<>();

  public String registration_endpoint;

  public List<String> response_modes_supported;

  public List<String> response_types_supported;

  public String revocation_endpoint;

  public List<String> revocation_endpoint_auth_methods_supported;

  public List<String> revocation_endpoint_auth_signing_alg_values_supported;

  public List<String> scopes_supported;

  public String service_documentation;

  public String token_endpoint;

  public List<String> token_endpoint_auth_methods_supported;

  public List<String> token_endpoint_auth_signing_alg_values_supported;

  public List<String> ui_locales_supported;

  @JsonAnyGetter
  public Map<String, Object> getOtherClaims() {
    return otherClaims;
  }

  @Override
  public String toString() {
    return new String(Mapper.prettyPrint(this));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    AuthorizationServerMetaData metaData = (AuthorizationServerMetaData) o;
    return Objects.equals(authorization_endpoint, metaData.authorization_endpoint) && Objects.equals(code_challenge_methods_supported, metaData.code_challenge_methods_supported) && Objects.equals(grant_types_supported, metaData.grant_types_supported) && Objects.equals(introspection_endpoint, metaData.introspection_endpoint) && Objects.equals(introspection_endpoint_auth_methods_supported, metaData.introspection_endpoint_auth_methods_supported) && Objects.equals(introspection_endpoint_auth_signing_alg_values_supported, metaData.introspection_endpoint_auth_signing_alg_values_supported) && Objects.equals(issuer, metaData.issuer) && Objects.equals(jwks_uri, metaData.jwks_uri) && Objects.equals(op_policy_uri, metaData.op_policy_uri) && Objects.equals(op_tos_uri, metaData.op_tos_uri) && Objects.equals(otherClaims, metaData.otherClaims) && Objects.equals(registration_endpoint, metaData.registration_endpoint) && Objects.equals(response_modes_supported, metaData.response_modes_supported) && Objects.equals(response_types_supported, metaData.response_types_supported) && Objects.equals(revocation_endpoint, metaData.revocation_endpoint) && Objects.equals(revocation_endpoint_auth_methods_supported, metaData.revocation_endpoint_auth_methods_supported) && Objects.equals(revocation_endpoint_auth_signing_alg_values_supported, metaData.revocation_endpoint_auth_signing_alg_values_supported) && Objects.equals(scopes_supported, metaData.scopes_supported) && Objects.equals(service_documentation, metaData.service_documentation) && Objects.equals(token_endpoint, metaData.token_endpoint) && Objects.equals(token_endpoint_auth_methods_supported, metaData.token_endpoint_auth_methods_supported) && Objects.equals(token_endpoint_auth_signing_alg_values_supported, metaData.token_endpoint_auth_signing_alg_values_supported) && Objects.equals(ui_locales_supported, metaData.ui_locales_supported);
  }

  @Override
  public int hashCode() {
    return Objects.hash(authorization_endpoint, code_challenge_methods_supported, grant_types_supported, introspection_endpoint, introspection_endpoint_auth_methods_supported, introspection_endpoint_auth_signing_alg_values_supported, issuer, jwks_uri, op_policy_uri, op_tos_uri, otherClaims, registration_endpoint, response_modes_supported, response_types_supported, revocation_endpoint, revocation_endpoint_auth_methods_supported, revocation_endpoint_auth_signing_alg_values_supported, scopes_supported, service_documentation, token_endpoint, token_endpoint_auth_methods_supported, token_endpoint_auth_signing_alg_values_supported, ui_locales_supported);
  }
}
