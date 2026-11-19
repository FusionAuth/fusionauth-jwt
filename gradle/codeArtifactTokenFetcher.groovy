/*
 * Copyright (c) 2026, Inversoft Inc., All Rights Reserved
 */
import groovy.json.JsonSlurper

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.time.Instant
import java.time.OffsetDateTime
import java.util.concurrent.TimeUnit

// Lazily fetches a CodeArtifact authorization token. Resolution order:
//   1. CODEARTIFACT_AUTH_TOKEN environment variable (CI)
//   2. Cached token in ~/.cache/code_artifact/<domain>/ if it has more than 30 minutes left
//   3. aws codeartifact get-authorization-token (triggers aws sso login when there is no session)
//
// Apply from settings.gradle. Exposes gradle.codeArtifactUrl and gradle.codeArtifactToken (a Provider) so
// build scripts can use them too.
//
// Optional Gradle properties:
//   codeArtifactProfile - AWS profile to use (defaults to AWS_PROFILE, then 'fusionauth-svc')

gradle.ext.codeArtifactUrl = 'https://hackfest-fusionauth-dev-011271748719.d.codeartifact.us-west-2.amazonaws.com/maven/hackfest-11-2026/'

def matcher = new URI(gradle.codeArtifactUrl).host =~ /^(.+)-(\d{12})\.d\.codeartifact\.([a-z0-9-]+)\.amazonaws\.com$/
if (!matcher.matches()) {
  throw new GradleException("Unable to parse CodeArtifact domain from [${gradle.codeArtifactUrl}]")
}
String domain = matcher.group(1)
String domainOwner = matcher.group(2)
String region = matcher.group(3)
String profile = (providers.gradleProperty('codeArtifactProfile').orNull ?: System.getenv('AWS_PROFILE')) ?: 'fusionauth-svc'
long bufferSeconds = 1800

Path cacheDir = Paths.get(System.getProperty('user.home'), '.cache', 'code_artifact', domain)
Path tokenPath = cacheDir.resolve('token')
Path expirationPath = cacheDir.resolve('token_expiration')

def aws = { List<String> args, boolean inheritIO ->
  List<String> command = ['aws'] + args + ['--region', region, '--profile', profile]
  def builder = new ProcessBuilder(command)
  if (inheritIO) {
    builder.inheritIO()
  } else {
    builder.redirectError(ProcessBuilder.Redirect.INHERIT)
  }
  def process = builder.start()
  String output = inheritIO ? '' : process.inputStream.text
  if (!process.waitFor(10, TimeUnit.MINUTES)) {
    process.destroyForcibly()
    throw new GradleException("Timed out running ${command.join(' ')}")
  }
  [exitCode: process.exitValue(), output: output]
}

def readCachedToken = {
  if (!Files.isRegularFile(tokenPath) || !Files.isRegularFile(expirationPath)) {
    logger.info('Cached CodeArtifact token does not exist')
    return null
  }
  long expiration = expirationPath.text.trim() as long
  if (Instant.now().epochSecond >= expiration - bufferSeconds) {
    logger.info('Cached CodeArtifact token is no longer valid')
    return null
  }
  logger.info('Cached CodeArtifact token is valid')
  tokenPath.text.trim()
}

def fetchToken = {
  if (aws(['sts', 'get-caller-identity'], false).exitCode != 0) {
    logger.lifecycle('No AWS session found, running aws sso login. You may be prompted to log in via a browser window.')
    if (aws(['sso', 'login'], true).exitCode != 0) {
      throw new GradleException('aws sso login failed')
    }
  }

  logger.lifecycle("Fetching CodeArtifact token for domain [${domain}]")
  def result = aws(['codeartifact', 'get-authorization-token', '--domain', domain, '--domain-owner', domainOwner, '--output', 'json'], false)
  if (result.exitCode != 0) {
    throw new GradleException('Unable to fetch CodeArtifact auth token')
  }

  def json = new JsonSlurper().parseText(result.output)
  String token = json.authorizationToken
  long expiration = OffsetDateTime.parse(json.expiration as String).toEpochSecond()
  Files.createDirectories(cacheDir)
  tokenPath.text = token
  expirationPath.text = expiration as String
  token
}

String cachedValue = null
gradle.ext.codeArtifactToken = providers.provider {
  if (cachedValue == null) {
    cachedValue = System.getenv('CODEARTIFACT_AUTH_TOKEN') ?: readCachedToken() ?: fetchToken()
  }
  cachedValue
}
