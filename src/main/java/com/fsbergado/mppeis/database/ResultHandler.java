package com.fsbergado.mppeis.database;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.RowSet;

/**
 * ResultHandler
 */
public class ResultHandler implements Handler<AsyncResult<RowSet<Row>>> {

    @Override
    public void handle(AsyncResult<RowSet<Row>> event) {

    }
}