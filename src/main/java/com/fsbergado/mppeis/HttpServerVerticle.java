package com.fsbergado.mppeis;

import java.util.HashSet;
import java.util.Set;

import com.fsbergado.mppeis.database.DatabaseVerticle;
import com.fsbergado.mppeis.user.UserServiceVerticle;
import com.fsbergado.mppeis.utils.RandomString;
import com.fsbergado.mppeis.utils.Validator;

import at.favre.lib.crypto.bcrypt.BCrypt;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.EventBus;
import io.vertx.core.http.Cookie;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.PemKeyCertOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.jwt.JWTOptions;
import io.vertx.ext.mail.MailClient;
import io.vertx.ext.mail.MailConfig;
import io.vertx.ext.mail.MailMessage;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.common.template.TemplateEngine;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.CSRFHandler;
import io.vertx.ext.web.handler.CorsHandler;
import io.vertx.ext.web.handler.LoggerHandler;
import io.vertx.ext.web.handler.StaticHandler;
import io.vertx.ext.web.handler.TemplateHandler;
import io.vertx.ext.web.templ.pebble.PebbleTemplateEngine;

/**
 * HttpServerVerticle
 */
public class HttpServerVerticle extends AbstractVerticle {

    public static final int HTTP_PORT = 8787;

    private EventBus eventBus;

    // private JWTOptions jwtOptions;

    @Override
    public void start(Promise<Void> startPromise) throws Exception {
        super.start(startPromise);

        final Router mainRouter = Router.router(vertx);
        
        // mainRouter.route().handler(createCorsHandler());
        mainRouter.route().handler(CSRFHandler.create(RandomString.generate(16)));
        mainRouter.post().handler(BodyHandler.create());
        mainRouter.put().handler(BodyHandler.create());
        mainRouter.route().handler(LoggerHandler.create());
        mainRouter.route().failureHandler(this::failureHandler);

        final TemplateEngine engine = PebbleTemplateEngine.create(vertx);
        final TemplateHandler templateHandler = TemplateHandler.create(engine);

        mainRouter.route("/static/*").handler(StaticHandler.create());
        mainRouter.get("/").handler(templateHandler);
        
        final Router authRouter = Router.router(vertx);
        
        authRouter.route().consumes("application/json");
        authRouter.post("/register").handler(this::registerHandler).handler(this::finalResponseHandler);
        authRouter.post("/login").handler(this::loginHandler).handler(this::finalResponseHandler);
        authRouter.get("/me").handler(this::customJWTAuthHandler).handler(this::meHandler).handler(this::finalResponseHandler);
        authRouter.get("/verify/:token").handler(this::verifyHandler).handler(this::finalResponseHandler);
        
        mainRouter.mountSubRouter("/auth", authRouter);

        final String keyPath = getClass().getClassLoader().getResource("keys/localhost.key").getFile();
        final String certPath = getClass().getClassLoader().getResource("keys/localhost.crt").getFile();

        vertx.createHttpServer(new HttpServerOptions().setSsl(true).setPemKeyCertOptions(new PemKeyCertOptions().setKeyPath(keyPath).setCertPath(certPath)).setLogActivity(true)).requestHandler(mainRouter).listen(HTTP_PORT, http -> {
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

    // CORS Handler
    private Handler<RoutingContext> createCorsHandler() {
        final Set<String> allowedHeaders = new HashSet<>();
        allowedHeaders.add("x-requested-with");
        allowedHeaders.add("Access-Control-Allow-Origin");
        allowedHeaders.add("origin");
        allowedHeaders.add("Content-Type");
        allowedHeaders.add("accept");
        allowedHeaders.add("X-XSRF-TOKEN");
        allowedHeaders.add("Authorization");

        final Set<HttpMethod> allowedMethods = new HashSet<>();
        allowedMethods.add(HttpMethod.GET);
        allowedMethods.add(HttpMethod.POST);
        allowedMethods.add(HttpMethod.OPTIONS);
        allowedMethods.add(HttpMethod.DELETE);
        allowedMethods.add(HttpMethod.PATCH);
        allowedMethods.add(HttpMethod.PUT);

        return CorsHandler.create("*").allowedHeaders(allowedHeaders).allowedMethods(allowedMethods);
    }

    // Handler that verifies user
    private void verifyHandler(RoutingContext ctx) {

        final String token = ctx.request().getParam("token");
        final JsonObject message = new JsonObject().put("token", token);
        final DeliveryOptions options = new DeliveryOptions().addHeader("action", "verify");

        // Invoke the user service to verify the supplied token
        eventBus.request(UserServiceVerticle.VERTX_EVENT_BUS_USER_SERVICE_ADDRESS, message, options, reply -> {
            if (reply.failed()) {
                ctx.fail(reply.cause());
                return;
            }            

            // Get the result
            final JsonObject result = (JsonObject) reply.result().body();

            // The response payload
            JsonObject payload = new JsonObject();

            // User with the specified token does not exist, respond with an error
            if (result.size() == 0) {
                ctx.put("payload", payload.put("error", "Invalid token."));
                ctx.response().setStatusCode(400);
                ctx.next();
                return;
            }

            // Token was found, return the user
            ctx.put("payload", payload.put("user", result.getJsonObject("user")));
            ctx.next();
        });
    }

    // Handler for user registration
    private void registerHandler(RoutingContext ctx) {
        final JsonObject body = ctx.getBodyAsJson();
        final String name = body.getString("name");
        final String email = body.getString("email");
        final HttpServerResponse response = ctx.response();
        final JsonObject responseBody = new JsonObject();
        final JsonArray errors = new JsonArray();
        boolean hasErrors = false;

        if (name.isEmpty()) {
            errors.add(new JsonObject().put("field", "name").put("error", "Name is required."));
            hasErrors = true;            
        }

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

        final String verification_token = RandomString.generate(32);
        final JsonObject message = new JsonObject().put("name", name).put("email", body.getString("email")).put("password", password).put("verification_token", verification_token);
        final DeliveryOptions options = new DeliveryOptions().addHeader("action", "register");

        eventBus.request(UserServiceVerticle.VERTX_EVENT_BUS_USER_SERVICE_ADDRESS, message, options, reply -> {
            if (reply.failed()) {
                ctx.fail(reply.cause());
                return;
            }

            final TemplateEngine engine = PebbleTemplateEngine.create(vertx);
            final JsonObject context = new JsonObject().put("name", name).put("verification_token", verification_token);
            final String template = getClass().getClassLoader().getResource("templates/email/registrationmail.peb").getFile();

            engine.render(context, template, ar -> {
                if (ar.failed()) {
                    ctx.fail(ar.cause());
                    return;
                }

                final Buffer buf = ar.result();
                
                final MailConfig config = new MailConfig();
                config.setHostname("localhost");
                config.setPort(1025);
                // config.setStarttls(StartTLSOptions.REQUIRED);
                config.setUsername("");
                config.setPassword("");
                final MailClient mailClient = MailClient.createNonShared(vertx, config);
    
                final MailMessage mail = new MailMessage();
                mail.setFrom("mppeis@mppeis.net (Admin User)");
                mail.setTo(email);
                // mail.setText("this is the plain message text");
                mail.setHtml(buf.toString());
    
                mailClient.sendMail(mail, ar2 -> {
                    if (ar2.failed()) {
                        ctx.fail(ar2.cause());
                        return;
                    }
                    response.setStatusCode(201);
                    ctx.put("payload", reply.result().body());
                    ctx.next();
                });
            });
        });
    }

    // User login handler
    private void loginHandler(RoutingContext ctx) {
        final JsonObject body = ctx.getBodyAsJson();
        final String email = body.getString("email");
        final JsonArray errors = new JsonArray();
        boolean hasErrors = false;

        // Validate input
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

        final String SQL_FIND_USER_BY_EMAIL = "SELECT id, name, email, password, role, is_active, email_verified_at FROM users WHERE email = $1";
        final JsonObject payload = new JsonObject().put("query", SQL_FIND_USER_BY_EMAIL).put("params",
                new JsonArray().add(email));
        final DeliveryOptions options = new DeliveryOptions().addHeader("action", "prepared-query");
        final String ERROR = "Invalid username or password.";        

        // Query the database for a user with the specified email
        eventBus.request(DatabaseVerticle.VERTX_EVENT_BUS_DATABASE_SERVICE_ADDRESS, payload, options, reply -> {
            if (reply.failed()) {
                ctx.fail(reply.cause());
                return;
            }

            final JsonObject body2 = (JsonObject) reply.result().body();
            final JsonArray result = body2.getJsonArray("result");

            // Get the query result
            final JsonObject user = (JsonObject) result.iterator().next();

            if (user.isEmpty()) {
                response.setStatusCode(401);
                ctx.put("payload", new JsonObject().put("error", ERROR));
                ctx.next();
                return;
            }

            // The user hasn't verified his/her email
            if (null == user.getString("email_verified_at")) {
                response.setStatusCode(401);
                ctx.put("payload", new JsonObject().put("error", "Please verify your email."));
                ctx.next();
                return;                
            }

            final Boolean active = user.getBoolean("is_active");

            // The user account is not active
            if (!active) {
                response.setStatusCode(401);
                ctx.put("payload", new JsonObject().put("error", "Your account is deactivated."));
                ctx.next();
                return;
            }

            // Check if the supplied password matches the hashed password stored in the database
            final String hashed = user.getString("password");
            final BCrypt.Result bcrypt = BCrypt.verifyer().verify(password.toCharArray(), hashed);

            if (!bcrypt.verified) {
                response.setStatusCode(401);
                ctx.put("payload", new JsonObject().put("error", ERROR));
                ctx.next();                
                return;
            }

            // Passwords match, generate the access token            
            // final List<String> audience = new ArrayList<>();
            // audience.add("http://localhost:" + HTTP_PORT);

            final JsonObject payload2 = new JsonObject().put("id", user.getInteger("id")).put("name", user.getString("name")).put("role", user.getInteger("role"));

            final String token = getAuthProvider().generateToken(payload2, new JWTOptions().setAlgorithm("RS256"));

            // Split the jwt token into two cookies to enhance api security
            final String[] jwt = token.split("\\.");
            final Cookie jwt1 = Cookie.cookie("session", String.join(".", jwt[0], jwt[1])).setSecure(true).setMaxAge(60 * 30);
            final Cookie jwt2 = Cookie.cookie("mppeis", jwt[2]).setSecure(true).setHttpOnly(true).setMaxAge(Long.MIN_VALUE);
            ctx.response().addCookie(jwt1).addCookie(jwt2);
            ctx.put("payload", new JsonObject().put("user", payload2));
            ctx.next();
        });
    }

    // Custom handler to authenticate the split jwt token
    private void customJWTAuthHandler(RoutingContext ctx) {

        final HttpServerRequest request = ctx.request();
        final Cookie jwt1 = request.getCookie("session");
        final Cookie jwt2 = request.getCookie("mppeis");
        final String header = request.getHeader("X-Requested-With");
        final String jwtPayload1 = jwt1.getValue();
        final String jwtPayload2 = jwt2.getValue();

        if (null != jwtPayload1 && !jwtPayload1.isEmpty() && null != jwtPayload2 && !jwtPayload2.isEmpty() && header.equals("XMLHttpRequest")) {
            final String jwt = String.join(".", jwtPayload1, jwtPayload2);
            final JsonObject authInfo = new JsonObject().put("jwt", jwt);
            getAuthProvider().authenticate(authInfo, authResult -> {
                if (authResult.failed()) {
                    ctx.fail(authResult.cause());
                    return;
                }

                // Set the logged in user
                ctx.setUser(authResult.result());

                // Generate a new cookie payload with fresh expiration time
                ctx.response().addCookie(jwt1.setMaxAge(60 * 30));
                ctx.next();
            });
        } else {
            ctx.fail(401);
        }
    }

    private void meHandler(RoutingContext ctx) {
        final JsonObject principal = ctx.user().principal();
        final JsonObject user = new JsonObject().put("id", principal.getInteger("id")).put("name", principal.getString("name")).put("email", principal.getString("email")).put("role", principal.getInteger("role"));
        ctx.put("payload", new JsonObject().put("user", user));
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
        response.putHeader("Content-Security-Policy", "script-src 'self'");
        response.putHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
        response.putHeader("Feature-Policy", "autoplay 'none'; camera 'none'");
        return ctx;
    }

    private void failureHandler(RoutingContext ctx) {
        final Throwable failure = ctx.failure();
        final HttpServerResponse response = ctx.response();
        if (failure.getMessage().equals("Unauthorized")) {
            response.setStatusCode(401);
        }
        if (failure.getMessage().equals("Forbidden")) {
            response.setStatusCode(403);
        }        
        if (response.getStatusCode() == 200) {
            response.setStatusCode(500);
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