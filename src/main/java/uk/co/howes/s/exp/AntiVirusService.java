package uk.co.howes.s.exp;

import io.vertx.core.Future;

public interface AntiVirusService {
    Future<AntiVirusServiceImpl.ScanResult> scanFile(String path);

    Future<String> ping();

    Future<String> version();
}
