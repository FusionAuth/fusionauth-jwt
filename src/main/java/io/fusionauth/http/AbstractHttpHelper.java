package io.fusionauth.http;

import io.fusionauth.jwks.JSONWebKeySetHelper;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * @author Daniel DeGroff
 */
public abstract class AbstractHttpHelper {

	private static volatile HttpClient HTTP_CLIENT = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(10000)).build();

	public static void setHttpClient(HttpClient client) {
		HTTP_CLIENT = client;
	}

	protected static <T> T get(HttpRequest request, Function<InputStream, T> consumer,
			BiFunction<String, Throwable, ? extends RuntimeException> exception) {
		String endpoint = request.uri().toString();

		HttpResponse<InputStream> response;
		try {
			response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofInputStream());
		} catch (Exception e) {
			throw exception.apply("Failed to make a request to [" + endpoint + "].", e);
		}

		int status = response.statusCode();
		if (status < 200 || status > 299) {
			throw exception.apply(
					"Failed to make a request to [" + endpoint + "], a status code of [" + status + "] was returned.",
					null);
		}

		try (InputStream is = response.body()) {
			return consumer.apply(is);
		} catch (Exception e) {
			throw exception.apply("Failed to parse the response as JSON from [" + endpoint + "].", e);
		}
	}

	protected static HttpRequest buildRequest(String endpoint, Consumer<HttpRequest.Builder> consumer) {
	    try {
	        HttpRequest.Builder builder = HttpRequest.newBuilder()
	            .uri(URI.create(endpoint))
	            .timeout(Duration.ofMillis(10_000))
	            .header("User-Agent", "fusionauth-jwt (https://github.com/FusionAuth/fusionauth-jwt)")
	            .GET();

	        if (consumer != null) {
	            consumer.accept(builder);
	        }

	        return builder.build();
	    } catch (Exception e) {
	        throw new JSONWebKeySetHelper.JSONWebKeySetException(
	            "Failed to build connection to [" + endpoint + "].", e);
	    }
	}	
	
}