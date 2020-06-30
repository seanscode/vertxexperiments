package uk.co.howes.s.exp;

import com.google.inject.Inject;
import io.vertx.core.AsyncResult;
import io.vertx.core.CompositeFuture;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.FileUpload;
import io.vertx.ext.web.RoutingContext;

import java.util.Set;

class ClamAVHandler {

    public static final int MAX_FILES = 1;
    public static final long MAX_FILE_SIZE = 1024 * 1024 * 150;
    private final AntiVirusService antiVirusService;

    @Inject
    public ClamAVHandler(AntiVirusService antiVirusService) {
        this.antiVirusService = antiVirusService;
    }

    public void handlePing(RoutingContext routingContext) {
        antiVirusService.ping().setHandler(outputCommandResult(routingContext));
    }

    public void handleVersion(RoutingContext routingContext) {
        antiVirusService.version().setHandler(outputCommandResult(routingContext));
    }

    public void handleScan(RoutingContext routingContext) {
        Set<FileUpload> fileUploads = routingContext.fileUploads();
        if (fileUploads.size() > MAX_FILES) {
            routingContext.response().setStatusCode(400).end("Max One File Per Request");
        } else {
            FileUpload upload = fileUploads.iterator().next();
            if (upload.size() < MAX_FILE_SIZE) {
                antiVirusService.scanFile(upload.uploadedFileName()).setHandler(handleScanResult(routingContext, upload));
            } else {
                routingContext.response().setStatusCode(400).end("File Too Large");
            }
        }
    }

    public void handlePingVersion(RoutingContext routingContext) {
        CompositeFuture.all(antiVirusService.ping(), antiVirusService.version()).setHandler(ar -> {
            CompositeFuture result = ar.result();
            Boolean pingResult = result.resultAt(0);
            routingContext.response().setStatusCode(200).end(pingResult + " " + result.resultAt(1));
        });
    }

    private Handler<AsyncResult<String>> outputCommandResult(RoutingContext routingContext) {
        return ar -> {
            if (ar.succeeded()) {
                routingContext.response().setStatusCode(200).end(ar.result());
            } else {
                routingContext.response().setStatusCode(500).end(ar.cause().getMessage());
            }
        };
    }

    private Handler<AsyncResult<AntiVirusServiceImpl.ScanResult>> handleScanResult(RoutingContext routingContext, FileUpload upload) {
        return ar -> {
            HttpServerResponse response = routingContext.response();
            if (ar.succeeded()) {
                String scanResult = String.valueOf(ar.result());
                String path = upload.uploadedFileName();
                routingContext.vertx().fileSystem().deleteBlocking(path);
                if (ar.result().isClean()) {
                    response.setStatusCode(200);
                } else {
                    response.setStatusCode(422);
                }
                response.end(scanResult);
            } else {
                response.setStatusCode(500).end(ar.cause().getMessage());
            }
        };
    }

}