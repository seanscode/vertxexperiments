package uk.co.howes.s.exp;

import com.google.inject.AbstractModule;
import com.google.inject.name.Names;
import io.vertx.core.Vertx;
import io.vertx.core.file.FileSystem;
import io.vertx.core.net.NetClient;


class AntiVirusModule extends AbstractModule {

    private final Vertx vertx;

    public AntiVirusModule(Vertx vertx) {
        this.vertx = vertx;
    }

    @Override
    protected void configure() {
        bind(FileSystem.class).toInstance(vertx.fileSystem());
        bind(NetClient.class).toInstance(vertx.createNetClient());
        bind(String.class).annotatedWith(Names.named("clam.host")).toInstance("192.168.56.101");
        bind(Integer.class).annotatedWith(Names.named("clam.port")).toInstance(3310);
    }
}