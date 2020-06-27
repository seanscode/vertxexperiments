package uk.co.howes.s.exp;

import com.google.inject.Inject;
import com.google.inject.name.Named;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.file.AsyncFile;
import io.vertx.core.file.FileSystem;
import io.vertx.core.file.OpenOptions;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.core.net.NetClient;
import io.vertx.core.net.NetSocket;

import java.nio.ByteBuffer;

class AntiVirusService {
    private static final Logger LOGGER = LoggerFactory.getLogger(AntiVirusService.class);
    private static final String FAILED_TO_CONNECT_TO_CLAM_AV = "Failed To Connect to CLAM AV";
    private static final String SOCKET_FAILED = "Socket Failed";
    private static final String FAILED_TO_OPEN_FILE = "Failed to Open File";

    private static final OpenOptions OPTIONS = new OpenOptions()
            .setRead(true).setWrite(false).
                    setCreateNew(false).setCreate(false);

    private static final String INSTREAM = "zINSTREAM\0";
    private static final byte[] ZERO_LENGTH_CHUNK = {0, 0, 0, 0};

    private final String host;
    private final int port;
    private final FileSystem fileSystem;
    private final NetClient tcpClient;

    @Inject
    public AntiVirusService(FileSystem fileSystem,
                            NetClient tcpClient,
                            @Named("clam.host")
                                    String host,
                            @Named("clam.port")
                                    int port) {
        this.fileSystem = fileSystem;
        this.tcpClient = tcpClient;
        this.host = host;
        this.port = port;
    }

    public Future<ScanResult> scanFile(String path) {
        Future<ScanResult> cleanFuture = Future.future();
        tcpClient.connect(port, host, streamFileToClamAv(path, cleanFuture));
        return cleanFuture;
    }

    public Future<String> ping() {
        return runClamCommand("PING");
    }

    public Future<String> version() {
        return runClamCommand("VERSION");
    }

    private Handler<AsyncResult<NetSocket>> streamFileToClamAv(String path, Future<ScanResult> cleanFuture) {
        return openSocket -> {
            if (openSocket.succeeded()) {
                NetSocket socket = openSocket.result();
                socket.handler(readClamAvResponse(cleanFuture, socket));
                socket.write(INSTREAM);

                openFile(path, cleanFuture, socket);
            } else {
                LOGGER.error(SOCKET_FAILED);
                cleanFuture.fail(SOCKET_FAILED);
            }
        };
    }

    private Future<String> runClamCommand(String command) {
        Future<String> responseFuture = Future.future();
        tcpClient.connect(port, host, handleCommandResponse(command, responseFuture));
        return responseFuture;
    }

    private Handler<AsyncResult<NetSocket>> handleCommandResponse(String command, Future<String> responseFuture) {
        return result -> {
            if (result.succeeded()) {
                NetSocket socket = result.result();
                socket.write(command);
                socket.handler(getResponse(responseFuture, socket));
            } else {
                LOGGER.error(FAILED_TO_CONNECT_TO_CLAM_AV);
                responseFuture.fail(FAILED_TO_CONNECT_TO_CLAM_AV);
            }
        };
    }


    private Handler<Buffer> readClamAvResponse(Future<ScanResult> cleanFuture, NetSocket socket) {
        return read -> {
            try {
                cleanFuture.complete(parseResult(read));
            } catch (Exception e) {
                cleanFuture.fail(e);
            }
            LOGGER.info("Scan Finished");
            socket.close();
        };
    }

    private ScanResult parseResult(Buffer buffer) {
        String response = buffer.getString(0, buffer.length());
        return new ScanResult(isClean(response), response);
    }

    private boolean isClean(String response) {
        return response.contains("OK") && !response.contains("FOUND");
    }

    private void openFile(String path, Future<ScanResult> cleanFuture, NetSocket socket) {
        fileSystem.open(path, OPTIONS, ar -> {
            if (ar.succeeded()) {
                sendFileToClam(socket, ar);
            } else {
                LOGGER.error(FAILED_TO_OPEN_FILE);
                cleanFuture.fail(FAILED_TO_OPEN_FILE);
            }
        });
    }

    private void sendFileToClam(NetSocket socket, AsyncResult<AsyncFile> ar) {
        AsyncFile asyncFile = ar.result();
        asyncFile.handler(writeChunk(socket));
        asyncFile.endHandler(writeZeroChunk(socket));
    }

    private Handler<Void> writeZeroChunk(NetSocket socket) {
        return eh -> socket.write(Buffer.buffer(ZERO_LENGTH_CHUNK));
    }

    private Handler<Buffer> writeChunk(NetSocket socket) {
        return data -> {
            byte[] bytes = data.getBytes();
            byte[] length = ByteBuffer.allocate(4).putInt(bytes.length).array();
            Buffer buffer = Buffer.buffer(bytes);
            Buffer lenBuffer = Buffer.buffer(length);

            socket.write(lenBuffer);
            socket.write(buffer);
        };
    }

    private Handler<Buffer> getResponse(Future<String> resultFuture, NetSocket socket) {
        return buffer -> {
            resultFuture.complete(buffer.getString(0, buffer.length()).trim());
            socket.close();
        };
    }

    public class ScanResult {
        private final boolean isClean;
        private final String result;


        private ScanResult(boolean isClean, String result) {
            this.isClean = isClean;
            this.result = result;
        }

        public boolean isClean() {
            return isClean;
        }

        @Override
        public String toString() {
            return "ScanResult{" +
                    "isClean=" + isClean +
                    ", result='" + result + '\'' +
                    '}';
        }
    }

}
