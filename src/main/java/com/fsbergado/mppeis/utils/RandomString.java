package com.fsbergado.mppeis.utils;

import java.util.Random;

/**
 * RandomString
 */
public class RandomString {

    // Generate a random sequence of string of specified length
    public static String generate(int length) {
        int leftLimit = 48; // numeral '0'
        int rightLimit = 122; // letter 'z'
        Random random = new Random();

        return random.ints(leftLimit, rightLimit + 1)
                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97)).limit(length)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString();        
    }
}