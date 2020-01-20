package com.fsbergado.mppeis.utils;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

/**
 * SecureNumberGenerator
 */
public class SecureNumberGenerator {

    public static void generate(int length) throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom secureRandomGenerator = SecureRandom.getInstance("SHA1PRNG", "SUN");

        // Get int length random bytes
        byte[] randomBytes = new byte[length];
        secureRandomGenerator.nextBytes(randomBytes);
        
    }
}