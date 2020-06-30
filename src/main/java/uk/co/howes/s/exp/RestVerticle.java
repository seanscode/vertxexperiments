package uk.co.howes.s.exp;

import com.google.inject.Guice;
import com.google.inject.Inject;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;

class RestVerticle extends AbstractVerticle {

    @Inject
    private ClamAVHandler clamAVHandler;

    public static void main(String[] args) {
        new RestVerticle().start();
    }

    @Override
    public void start() {
        vertx = Vertx.vertx();
        Guice.createInjector(new AntiVirusModule(vertx)).injectMembers(this);

        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());
        router.route(HttpMethod.POST, "/scan/").handler(clamAVHandler::handleScan);
        router.route(HttpMethod.POST, "/ping-version/").handler(clamAVHandler::handlePingVersion);
        router.route(HttpMethod.GET, "/ping").handler(clamAVHandler::handlePing);
        router.route(HttpMethod.GET, "/version").handler(clamAVHandler::handleVersion);

        vertx.createHttpServer()
                .requestHandler(router)
                .listen(9090,
                        result -> {
                            if (result.succeeded()) {
                                System.out.println("Clam AV Service Started");
                            } else {
                                System.out.println("Its all gone wrong");
                            }
                        }
                );
    }
}
