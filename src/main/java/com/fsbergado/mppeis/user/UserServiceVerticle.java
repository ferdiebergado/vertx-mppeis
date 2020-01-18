package com.fsbergado.mppeis.user;

import com.fsbergado.mppeis.database.DatabaseVerticle;
import com.fsbergado.mppeis.eventbus.FailedMessageHandler;

import at.favre.lib.crypto.bcrypt.BCrypt;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.EventBus;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * UserServiceVerticle
 */
public class UserServiceVerticle extends AbstractVerticle {

    public static final String VERTX_EVENT_BUS_USER_SERVICE_ADDRESS = "user.service.queue";

    private EventBus eventBus;

    @Override
    public void start(Promise<Void> startPromise) throws Exception {
        super.start(startPromise);

        eventBus = vertx.eventBus();

        eventBus.consumer(VERTX_EVENT_BUS_USER_SERVICE_ADDRESS, this::userHandler);        
    }    

    public void userHandler(Message<JsonObject> message) {
        if (!message.headers().contains("action")) {
            message.fail(404, "No action header specified");
            return;
        }

        final String action = message.headers().get("action");

        switch (action) {
        case "register":
            register(message);
            break;
        default:
            message.fail(400, "Invalid action: " + action);
            break;
        }
    }

    private void register(Message<JsonObject> message) {
        final JsonObject body = message.body();
        final String email = body.getString("email");
        final String password = body.getString("password");
        final String hashed = BCrypt.withDefaults().hashToString(12, password.toCharArray());
        final String SQL_REGISTER = "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, created_at, updated_at";
        final JsonObject payload = new JsonObject().put("query", SQL_REGISTER).put("params",
                new JsonArray().add(email).add(hashed));
        final DeliveryOptions options = new DeliveryOptions().addHeader("action", "prepared-query");

        eventBus.request(DatabaseVerticle.VERTX_EVENT_BUS_DATABASE_SERVICE_ADDRESS, payload, options,
            reply -> {
                if (reply.failed()) {
                    FailedMessageHandler.reply(reply.cause(), message);
                    return;
                }

                final JsonObject body2 = (JsonObject) reply.result().body();
                final JsonArray result = body2.getJsonArray("result");
                final JsonObject user = (JsonObject) result.iterator().next();

                message.reply(user);
        });
    }
}