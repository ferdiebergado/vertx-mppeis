package com.fsbergado.mppeis;

import com.fsbergado.mppeis.database.DatabaseVerticle;
import com.fsbergado.mppeis.user.UserServiceVerticle;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;

public class MainVerticle extends AbstractVerticle {

  @Override
  public void start(Promise<Void> startPromise) throws Exception {

    Promise<String> dbVerticleDeployment = Promise.promise();

    vertx.deployVerticle(new DatabaseVerticle(), dbVerticleDeployment);

    dbVerticleDeployment.future().compose(id -> {
      Promise<String> userServiceVerticleDeployment = Promise.promise();
      vertx.deployVerticle(new UserServiceVerticle(), userServiceVerticleDeployment);

      return userServiceVerticleDeployment.future();
    }).setHandler(ar -> {
      if (ar.failed()) {
        startPromise.fail(ar.cause());
        return;
      }

      vertx.deployVerticle(new HttpServerVerticle());

      startPromise.complete();
    });
  }
}
