package com.scascanner.service;

import com.scascanner.model.ScanResult;

import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory scan-result store (bonus: assignment section 11, "incremental / persisted
 * results"). A real deployment would back this with a database so results survive a restart
 * and are queryable across instances; kept as its own small class so that swap doesn't touch
 * ScanService or the API layer - both only ever call save/get.
 */
public class ScanStore {

    private final ConcurrentHashMap<String, ScanResult> results = new ConcurrentHashMap<>();

    public void save(ScanResult result) {
        results.put(result.scanId(), result);
    }

    public ScanResult get(String scanId) {
        return results.get(scanId);
    }
}
