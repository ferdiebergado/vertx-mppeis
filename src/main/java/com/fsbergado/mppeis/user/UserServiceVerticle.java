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
        case "verify":
            verify(message);
            break;
        default:
            message.fail(400, "Invalid action: " + action);
            break;
        }
    }

    private void register(Message<JsonObject> message) {
        final JsonObject body = message.body();
        final String name = body.getString("name");
        final String email = body.getString("email");
        final String password = body.getString("password");
        final String hashed = BCrypt.withDefaults().hashToString(12, password.toCharArray());
        final String verification_token = body.getString("verification_token");
        final String SQL_REGISTER = "INSERT INTO users (name, email, password, verification_token) VALUES ($1, $2, $3, $4) RETURNING id, email, created_at, updated_at";
        final JsonObject payload = new JsonObject().put("query", SQL_REGISTER).put("params",
                new JsonArray().add(name).add(email).add(hashed).add(verification_token));
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

    private void verify(Message<JsonObject> message) {
        final JsonObject body = message.body();
        final String token = body.getString("token");       
        final String SQL_FIND_USER_BY_VERIFICATION_TOKEN = "SELECT id FROM users WHERE verification_token = $1";
        final JsonObject payload = new JsonObject().put("query", SQL_FIND_USER_BY_VERIFICATION_TOKEN).put("params",
                new JsonArray().add(token));
        final DeliveryOptions options = new DeliveryOptions().addHeader("action", "prepared-query");

        // Query the database for a user with the matching verification token
        eventBus.request(DatabaseVerticle.VERTX_EVENT_BUS_DATABASE_SERVICE_ADDRESS, payload, options, reply -> {
            if (reply.failed()) {
                FailedMessageHandler.reply(reply.cause(), message);
                return;
            }

            final JsonObject body2 = (JsonObject) reply.result().body();
            final JsonArray result = body2.getJsonArray("result");

            // User was found
            if (result.size() == 1) {
                final JsonObject user = (JsonObject) result.iterator().next();
                final String SQL_UPDATE_USER_STATUS = "UPDATE users SET email_verified_at = CURRENT_TIMESTAMP, verification_token = NULL, is_active = TRUE WHERE id = $1 returning id, name, email, role, is_active";
                final JsonObject payload2 = new JsonObject().put("query", SQL_UPDATE_USER_STATUS).put("params", new JsonArray() .add(user.getInteger("id")));

                // Update the user status
                eventBus.request(DatabaseVerticle.VERTX_EVENT_BUS_DATABASE_SERVICE_ADDRESS, payload2, options, reply2 -> {
                    if (reply2.failed()) {
                        FailedMessageHandler.reply(reply2.cause(), message);
                        return;
                    }                    

                    final JsonObject body3 = (JsonObject) reply2.result().body();
                    final JsonArray result2 = body3.getJsonArray("result");

                    message.reply(new JsonObject().put("user", (JsonObject) result2.iterator().next()));
                    return;
                });
            } else {
                message.reply(new JsonObject().put("user", new JsonObject()));            
            }
        });
    }   
}