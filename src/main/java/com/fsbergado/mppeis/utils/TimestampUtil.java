package com.fsbergado.mppeis.utils;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;

/**
 * TimestampUtil
 */
public class TimestampUtil {

    public static final String TIMESTAMP_FORMAT = "yyyy-MM-dd hh:mm:ss x";

    public static String format(OffsetDateTime timestamp) {

        if (null == timestamp) {
            return null;
        }

        final DateTimeFormatter formatter = DateTimeFormatter.ofPattern(TIMESTAMP_FORMAT);

        return formatter.format(timestamp);
    }
}