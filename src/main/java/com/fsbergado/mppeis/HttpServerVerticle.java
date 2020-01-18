package com.fsbergado.mppeis;

import com.fsbergado.mppeis.database.DatabaseVerticle;
import com.fsbergado.mppeis.user.UserServiceVerticle;
import com.fsbergado.mppeis.utils.Validator;

import at.favre.lib.crypto.bcrypt.BCrypt;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.EventBus;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.jwt.JWTOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.JWTAuthHandler;

/**
 * HttpServerVerticle
 */
public class HttpServerVerticle extends AbstractVerticle {

    public static final int HTTP_PORT = 8787;

    private EventBus eventBus;

    @Override
    public void start(Promise<Void> startPromise) throws Exception {
        super.start(startPromise);

        final Router mainRouter = Router.router(vertx);

        mainRouter.route().consumes(RESPONSE_CONTENT_TYPE);
        mainRouter.post().handler(BodyHandler.create());
        mainRouter.put().handler(BodyHandler.create());
        mainRouter.route().failureHandler(this::failureHandler);
        
        final Router authRouter = Router.router(vertx);
        
        authRouter.post("/register").handler(this::registerHandler).handler(this::finalResponseHandler);
        authRouter.post("/login").handler(this::loginHandler).handler(this::finalResponseHandler);
        authRouter.get("/me").handler(JWTAuthHandler.create(getAuthProvider())).handler(this::meHandler).handler(this::finalResponseHandler);
        
        mainRouter.mountSubRouter("/auth", authRouter);

        vertx.createHttpServer(new HttpServerOptions().setLogActivity(true)).requestHandler(mainRouter).listen(HTTP_PORT, http -> {
            if (http.failed()) {
                startPromise.fail(http.cause());                
                http.cause().printStackTrace();
                System.out.println("Failed starting HTTP server.");
            } else {
                System.out.println("HTTP server listening on port " + HTTP_PORT + "...");
                eventBus = vertx.eventBus();
                startPromise.future();
            }
        });
    }

    private void registerHandler(RoutingContext ctx) {
        final JsonObject body = ctx.getBodyAsJson();
        final String email = body.getString("email");
        final HttpServerResponse response = ctx.response();
        final JsonObject responseBody = new JsonObject();
        final JsonArray errors = new JsonArray();
        boolean hasErrors = false;

        if (email.isEmpty()) {
            errors.add(new JsonObject().put("field", "email").put("error", "Email is required."));
            hasErrors = true;
        } else {
            if (!Validator.validateEmail(email)) {
                errors.add(new JsonObject().put("field", "email").put("error", "Email is not a valid email."));
                hasErrors = true;
            }
        }

        final String password = body.getString("password");
        final String password_confirmation = body.getString("password_confirmation");

        if (password.isEmpty()) {
            errors.add(new JsonObject().put("field", "password").put("error", "Password is required."));
            hasErrors = true;
        } else {
            if (!password.equals(password_confirmation)) {
                errors.add(new JsonObject().put("field", "password").put("error", "Passwords do not match."));
                hasErrors = true;
            }
        }

        if (password_confirmation.isEmpty()) {
            errors.add(new JsonObject().put("field", "password_confirmation").put("error",
                    "Password confirmation is required."));
            hasErrors = true;
        }

        if (hasErrors) {
            responseBody.put("errors", errors);
            response.setStatusCode(400);
            ctx.put("payload", responseBody);
            ctx.next();
            return;
        }

        final JsonObject message = new JsonObject().put("email", body.getString("email")).put("password", password);
        final DeliveryOptions options = new DeliveryOptions().addHeader("action", "register");

        eventBus.request(UserServiceVerticle.VERTX_EVENT_BUS_USER_SERVICE_ADDRESS, message, options, reply -> {
            if (reply.failed()) {
                ctx.fail(reply.cause());
                return;
            }
            response.setStatusCode(201);
            ctx.put("payload", reply.result().body());
            ctx.next();
        });
    }

    private void loginHandler(RoutingContext ctx) {
        final JsonObject body = ctx.getBodyAsJson();
        final String email = body.getString("email");
        final JsonArray errors = new JsonArray();
        boolean hasErrors = false;

        if (email.isEmpty()) {
            errors.add(new JsonObject().put("field", "email").put("error", "Email is required."));
            hasErrors = true;
        } else {
            if (!Validator.validateEmail(email)) {
                errors.add(new JsonObject().put("field", "email").put("error", "Email is not a valid email."));
                hasErrors = true;
            }
        }

        final String password = body.getString("password");

        if (password.isEmpty()) {
            errors.add(new JsonObject().put("field", "password").put("error", "Password is required."));
            hasErrors = true;
        }

        final HttpServerResponse response = ctx.response();
        final JsonObject responseBody = new JsonObject();

        if (hasErrors) {
            response.setStatusCode(400);
            responseBody.put("errors", errors);
            ctx.put("payload", responseBody);
            ctx.next();
            return;
        }            

        final String SQL_FIND_USER_BY_EMAIL = "SELECT password, role FROM users WHERE email = $1";
        final JsonObject payload = new JsonObject().put("query", SQL_FIND_USER_BY_EMAIL).put("params",
                new JsonArray().add(email));
        final DeliveryOptions options = new DeliveryOptions().addHeader("action", "prepared-query");
        final String ERROR = "Invalid username or password.";        

        eventBus.request(DatabaseVerticle.VERTX_EVENT_BUS_DATABASE_SERVICE_ADDRESS, payload, options, reply -> {
            if (reply.failed()) {
                ctx.fail(reply.cause());
                return;
            }

            final JsonObject body2 = (JsonObject) reply.result().body();
            final JsonArray result = body2.getJsonArray("result");

            if (result.isEmpty()) {
                response.setStatusCode(401);
                ctx.put("payload", new JsonObject().put("error", ERROR));
                ctx.next();
                return;
            }

            final JsonObject user = (JsonObject) result.iterator().next();
            final String hashed = user.getString("password");
            final BCrypt.Result bcrypt = BCrypt.verifyer().verify(password.toCharArray(), hashed);

            if (!bcrypt.verified) {
                response.setStatusCode(401);
                ctx.put("payload", new JsonObject().put("error", ERROR));
                ctx.next();                
                return;
            }

            final String token = getAuthProvider().generateToken(new JsonObject().put("user", email).put("role", user.getInteger("role")), new JWTOptions().setAlgorithm("RS256").setSubject("MPPEIS API").setIssuer("MPPEIS"));

            ctx.put("payload", new JsonObject().put("access_token", token));
            ctx.next();
        });
    }

    private void meHandler(RoutingContext ctx) {
        final JsonObject principal = ctx.user().principal();
        ctx.put("payload", new JsonObject().put("user", principal.getString("user")).put("role", principal.getInteger("role")));
        ctx.next();
    }

    private JWTAuth getAuthProvider() {
        return JWTAuth.create(vertx,
                new JWTAuthOptions().addPubSecKey(new PubSecKeyOptions().setAlgorithm("RS256")
                        .setPublicKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtyfDKsgLEbZUD2U+cx4C\n"
                                + "H6aEsSknRnDrEPcCIaSBd7rJu6dpQf4JcD9N0M1Y8stcsekO1h4RUjHx78AT6BA0\n"
                                + "6PTgbj6QQwo0hWNyrtXjF6NkwsjQyAT4W2KZJlVCeMuMjZHnYoM55mqY6AlQLD3c\n"
                                + "sxWrgQJbWSmCYFf2oQQNCV71ul66UqXrF07fGF5tYJxFEEnt+qEasVCppsl8Cz2E\n"
                                + "5XXRtS9zJMETW48B/Y0mW4RZ/+DcJvjYoN1qNUQM9MTrWB/RxjhkygzEimsLP1w7\n"
                                + "DhtjNYKE4CQf+mZ3sHqttQR7bLLjtWas7M10QjjDa/PwxBkDYVEG8/LAbzpnYz+W\n" + "4wIDAQAB")
                        .setSecretKey("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3J8MqyAsRtlQP\n"
                                + "ZT5zHgIfpoSxKSdGcOsQ9wIhpIF3usm7p2lB/glwP03QzVjyy1yx6Q7WHhFSMfHv\n"
                                + "wBPoEDTo9OBuPpBDCjSFY3Ku1eMXo2TCyNDIBPhbYpkmVUJ4y4yNkedigznmapjo\n"
                                + "CVAsPdyzFauBAltZKYJgV/ahBA0JXvW6XrpSpesXTt8YXm1gnEUQSe36oRqxUKmm\n"
                                + "yXwLPYTlddG1L3MkwRNbjwH9jSZbhFn/4Nwm+Nig3Wo1RAz0xOtYH9HGOGTKDMSK\n"
                                + "aws/XDsOG2M1goTgJB/6Zneweq21BHtssuO1ZqzszXRCOMNr8/DEGQNhUQbz8sBv\n"
                                + "OmdjP5bjAgMBAAECggEAHdvBmWvbQhvzQD9FGwc9WWOQJkGLQZSO/ckG8+0Znic5\n"
                                + "U/pK0pNTfpUTXoLbiVlV1zsjTAzCzh+OTYOGu0JJHeEt5UsVwZgcT9KSk6YSy3u7\n"
                                + "pXWPc8w7oMpGJVWo7IBifYHXstupyMKAAvPhuhSrshZKS1HTCooV0xcEAePjLC+k\n"
                                + "Bfy34MYq4LCBYaSkogndKmx+hb5DFIbbNLwH0IRkjLyFw82A53xYb9aPsAGSuG2j\n"
                                + "/r/UiI0Rt9mIA9zroQvI1crpK8CarG0xnsCPLMDYfaBmXAdGRHIVTivXf5fOqwHl\n"
                                + "60y4As0M39walYiKaBuMZ3VLSA9ydvTLAWjm9zkSIQKBgQDss66jPco+Gsp+Dk15\n"
                                + "Snemo+UkSAzN2WNCu1yc31ixHIOhr6twVVW08N+o3HHqSd+PQRMOqKxf4+DIR5De\n"
                                + "+BAg/FpYUQ93aNDisOgDiLa/hKMYI897MHiJXUXBmnzz84tdxHOJKceiXgw6qv1I\n"
                                + "gC0W1NKMHlP/vvijSetOe7RVtQKBgQDGFnwAhbawLTiEQi603GKNpM5itQ1tdaP9\n"
                                + "4lafbAI51P8pl5mPGj5rcnjrhJAA4pNWkp+4A94BMswjef5VbYdpOv+tPt6W/9v9\n"
                                + "KqPDP8yOpYfqizDTinlrek8PVJgTlxisoM3j/2As2RtCj5X1ZPkPuiMIn/zfLqtI\n"
                                + "aiCalCiZNwKBgDV1Cx7g6JkIEe1QK50V/VnMMAb2orWmv+0lRXBEXNJ7HxtYAj73\n"
                                + "dsjLkaegSbXhAzVmO/iWjX+GhpCU4RoKKhJZC8pgXD7alDpuO6f4q1Urjm34QHaQ\n"
                                + "5tgXEZb83fV2bmY55OH4Zpa76MUjMtq53/UFEZwFiXD730l5e0QZWgv1AoGBAK0t\n"
                                + "2xtZy24bGt4GPm9Afaj3/LevMh4QS18bEkAuXYPSA4KJV2cUup2VZsIBEySy8b0u\n"
                                + "UxS9zMmfb3lUnlZxe4E0Y3NDE7dP2TRsot+AV4YekcUsC3PmDGE6fQQaIRp/bsL9\n"
                                + "kwNRsPOEm6CFh8USkex9/0L7HEjCtFyK7BY4kYXhAoGAQFG3xzA96dCKZbLbK3kV\n"
                                + "3yM0+o54HFM32NhmK4c0frh+ilWCjmQ4Hf93yMZHMWbfSFmW6VP2LTFJzadObjPc\n"
                                + "zW3AFoCiS2G7vm8K6fVXK4+OjxCGNGUffEk1QStugavp0nyDpfFyoJFcTopEF3Ka\n"
                                + "AdjkVx42lYsSMBK0SNErAnA=")));        
    }

    private RoutingContext setResponseHeaders(RoutingContext ctx) {
        final HttpServerResponse response = ctx.response();
        response.putHeader("X-Frame-Options", "SAMEORIGIN");
        response.putHeader("X-XSS-Protection", "1; mode=block");
        response.putHeader("X-Content-Type-Options", "nosniff");
        response.putHeader("Content-Type", "application/json");
        return ctx;
    }

    private void failureHandler(RoutingContext ctx) {
        final Throwable failure = ctx.failure();
        final HttpServerResponse response = ctx.response();
        if (failure.getMessage().equals("Unauthorized")) {
            response.setStatusCode(401);
        }
        failure.printStackTrace();
        final JsonObject payload = new JsonObject().put("error", failure.getMessage());
        final RoutingContext newctx = setResponseHeaders(ctx);
        newctx.response().end(Json.encodeToBuffer(payload));
    }

    private void finalResponseHandler(RoutingContext ctx) {
        final RoutingContext newctx = setResponseHeaders(ctx);
        newctx.response().end(Json.encodeToBuffer(ctx.get("payload")));
    }
}