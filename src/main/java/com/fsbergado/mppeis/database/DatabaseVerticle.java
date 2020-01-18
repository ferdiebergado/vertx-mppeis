package com.fsbergado.mppeis.database;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

import com.fsbergado.mppeis.utils.TimestampUtil;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.pgclient.PgConnectOptions;
import io.vertx.pgclient.PgPool;
import io.vertx.sqlclient.PoolOptions;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.RowSet;
import io.vertx.sqlclient.Tuple;

/**
 * DatabaseVerticle
 */
public class DatabaseVerticle extends AbstractVerticle {

    public static final String VERTX_EVENT_BUS_DATABASE_SERVICE_ADDRESS = "db.service.queue";
    private final int POOL_MAX_SIZE = 5;

    private PgPool pool;

    @Override
    public void start(Promise<Void> startPromise) throws Exception {
        super.start(startPromise);

        final PgConnectOptions connectOptions = new PgConnectOptions()
                .setPort(Integer.valueOf(System.getenv("PGPORT"))).setHost(System.getenv("PGHOST"))
                .setDatabase(System.getenv("PGDATABASE")).setUser(System.getenv("PGUSER"))
                .setPassword(System.getenv("PGPASSWORD")).setCachePreparedStatements(true);

        // Pool options
        final PoolOptions poolOptions = new PoolOptions().setMaxSize(POOL_MAX_SIZE);

        // Create the pooled client
        pool = PgPool.pool(vertx, connectOptions, poolOptions);

        pool.getConnection(ar -> {
            if (ar.failed()) {
                ar.cause().printStackTrace();
                System.out.println("Failed starting the database verticle.");
                startPromise.fail(ar.cause());
            }

            vertx.eventBus().consumer(VERTX_EVENT_BUS_DATABASE_SERVICE_ADDRESS, this::handleMessage);
            System.out.println("Database verticle listening on event bus address : " + VERTX_EVENT_BUS_DATABASE_SERVICE_ADDRESS);
            startPromise.future();
        });
    }

    // Handle the event bus message
    private void handleMessage(Message<JsonObject> message) {

        if (!message.headers().contains("action")) {
            message.fail(404, "No action header specified");
            return;
        }

        final String action = message.headers().get("action");

        switch (action) {
            case "prepared-query":
                preparedQuery(message);
                break;
            case "query":
                query(message);
                break;
            default:
                message.fail(400, "Bad action: " + action);
                break;
        }
    }

    // Execute a prepared statement
    private void preparedQuery(Message<JsonObject> message) {

        final JsonObject body = message.body();
        final String sql = body.getString("query");
        final JsonArray data = body.getJsonArray("params");
        final List<Object> params = new ArrayList<>();
        
        data.forEach(p -> params.add(p));

        pool.preparedQuery(sql, Tuple.wrap(params), ar -> {
            if (ar.failed()) {
                sendFailureMessage(ar.cause(), message);
                return;
            }
            sendResult(ar.result(), message);
        });
    }

    // Execute a plain query
    private void query(Message<JsonObject> message) {
        final String sql = message.body().getString("query");

        pool.query(sql, ar -> {
            if (ar.failed()) {
                sendFailureMessage(ar.cause(), message);
                return;
            }
            sendResult(ar.result(), message);
        });
    }

    // Return the failure message
    private void sendFailureMessage(Throwable cause, Message<JsonObject> message) {
        cause.printStackTrace();
        message.fail(500, cause.getMessage());
    }
    
    private void sendResult(RowSet<Row> rows, Message<JsonObject> message) {
        final JsonArray result = new JsonArray();

        // Build a JsonObject from the column names and values of each row
        rows.forEach(row -> {
            JsonObject data = new JsonObject();
            for (int j = 0; j < row.size(); j++) {
                String column = row.getColumnName(j);
                Object value = row.getValue(j);
                if (column.equals("created_at") || column.equals("updated_at") || column.equals("deleted_at") || column.equals("email_verified_at")) {
                    value = TimestampUtil.format((OffsetDateTime) value);
                }
                data.put(column, value);
            }
            result.add(data);
        });

        // send the reply
        message.reply(new JsonObject().put("result", result));
    }
}