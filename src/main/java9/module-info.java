module io.fusionauth {
	exports io.fusionauth.jwt.hmac;
	exports io.fusionauth.jwt.json;
	exports io.fusionauth.pem.domain;
	exports io.fusionauth.jwks.domain;
	exports io.fusionauth.jwks;
	exports io.fusionauth.der;
	exports io.fusionauth.jwt.domain;
	exports io.fusionauth.jwt.ec;
	exports io.fusionauth.jwt.rsa;
	exports io.fusionauth.jwt;
	exports io.fusionauth.pem;
	exports io.fusionauth.security;

	requires com.fasterxml.jackson.annotation;
	requires com.fasterxml.jackson.core;
	requires com.fasterxml.jackson.databind;
}