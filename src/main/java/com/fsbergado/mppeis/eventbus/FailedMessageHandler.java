package com.fsbergado.mppeis.eventbus;

import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonObject;

/**
 * FailedMessageHandler
 */
public class FailedMessageHandler {

    public static void reply(Throwable failure, Message<JsonObject> message) {
        failure.printStackTrace();
        message.fail(500, failure.getMessage());        
    }
}