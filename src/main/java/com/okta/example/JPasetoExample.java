package com.okta.example;

import dev.paseto.jpaseto.Paseto;
import dev.paseto.jpaseto.PasetoParser;
import dev.paseto.jpaseto.Pasetos;
import dev.paseto.jpaseto.Version;
import dev.paseto.jpaseto.lang.Keys;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Random;

public class JPasetoExample {

    private static final SecretKey SHARED_SECRET = Keys.secretKey();
    private static final KeyPair KEY_PAIR = Keys.keyPairFor(Version.V1);

    public static void main(String[] args) {

        String tokenString = createToken();
        log("Paseto token: "+ tokenString);

        Paseto result = parseToken(tokenString);
        log("Token Claims:");
        result.getClaims().forEach((key, value) -> log("    "+ key + ": " + value));

        String audience = result.getClaims().getAudience();
        log("Audience: "+ audience);

        int rolledValue = result.getClaims().get("1d20", Integer.class);
        log("1d20 rolled: " + rolledValue);

        parseTokenWithRequirements(tokenString);
    }

    public static String createToken() {
        Instant now = Instant.now();

        String token = Pasetos.V1.LOCAL.builder()
                .setSharedSecret(SHARED_SECRET)
                .setIssuedAt(now)
                .setExpiration(now.plus(1, ChronoUnit.HOURS))
                .setAudience("blog-post")
                .setIssuer("https://developer.okta.com/blog/")
                .claim("1d20", new Random().nextInt(20) + 1)
                .compact();

        return token;
    }

    public static Paseto parseToken(String token) {
        PasetoParser parser = Pasetos.parserBuilder()
                .setSharedSecret(SHARED_SECRET)
                .setPublicKey(KEY_PAIR.getPublic())
                .build();

        Paseto result = parser.parse(token);
        return result;
    }

    public static Paseto parseTokenWithRequirements(String token) {
        PasetoParser parser = Pasetos.parserBuilder()
                .setSharedSecret(SHARED_SECRET)
                .setPublicKey(KEY_PAIR.getPublic())
                .requireAudience("blog-post")
                .requireIssuer("https://developer.okta.com/blog/")
                .build();

        Paseto result = parser.parse(token);
        return result;
    }

    private static void log(String message) {
        System.out.println(message);
    }
}