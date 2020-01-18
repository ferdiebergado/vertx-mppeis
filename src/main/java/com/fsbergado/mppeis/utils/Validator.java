package com.fsbergado.mppeis.utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Validator
 */
public class Validator {

    public static Boolean validateEmail(final String email) {
        final String regex = "^[\\w!#$%&'*+/=?`{|}~^-]+(?:\\.[\\w!#$%&'*+/=?`{|}~^-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,6}$";
        final Pattern pattern = Pattern.compile(regex);
        final Matcher matcher = pattern.matcher(email);

        return matcher.matches();        
    }
}