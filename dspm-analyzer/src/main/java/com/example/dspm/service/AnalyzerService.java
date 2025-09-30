package com.example.dspm.service;

import com.example.dspm.domain.*;
import com.example.dspm.repo.*;
import com.example.dspm.web.dto.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.*;

@Service
public class AnalyzerService {

    private final DataObjectRepo dataRepo;
    private final ObjectProfileRepo profileRepo;
    private final PseudonymizationGuardRepo guardRepo;

    public AnalyzerService(DataObjectRepo dataRepo, ObjectProfileRepo profileRepo, PseudonymizationGuardRepo guardRepo) {
        this.dataRepo = dataRepo;
        this.profileRepo = profileRepo;
        this.guardRepo = guardRepo;
    }

    private OffsetDateTime parseIso(String s) {
        if (s == null || s.isBlank()) return null;
        try {
            String s2 = s.replace("Z", "+00:00");
            return OffsetDateTime.parse(s2);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private Map<String, Object> mergeExtra(AssetIn item) {
        Map<String, Object> m = new HashMap<>();
        if (item.meta() != null) m.putAll(item.meta());
        m.putIfAbsent("display_name", item.name());
        m.putIfAbsent("region", item.region());
        return m;
    }

    // text profiling (파이썬 로직을 자바로 이식)
    public static Map<String, Object> profileText(String s) {
        Map<String, Object> out = new HashMap<>();
        if (s == null || s.isEmpty()) {
            out.put("line_count", 0L);
            out.put("avg_line_len", 0.0);
            out.put("max_line_len", 0L);
            out.put("ratio_digit", 0.0);
            out.put("ratio_alpha", 0.0);
            out.put("ratio_symbol", 0.0);
            out.put("has_csv_header", false);
            return out;
        }
        String[] lines = s.split("\\R", -1);
        int ln = Math.min(lines.length, 5000);
        long max = 0L;
        long sum = 0L;
        for (int i = 0; i < ln; i++) {
            int len = lines[i].length();
            sum += len;
            if (len > max) max = len;
        }
        double avg = ln == 0 ? 0.0 : (double) sum / ln;

        String sample = s.length() > 200_000 ? s.substring(0, 200_000) : s;
        int total = sample.length() == 0 ? 1 : sample.length();
        long digits = sample.chars().filter(Character::isDigit).count();
        long alphas = sample.chars().filter(Character::isAlphabetic).count();
        double rd = (double) digits / total;
        double ra = (double) alphas / total;
        double rs = Math.max(0.0, 1.0 - rd - ra);
        boolean hasCsv = ln > 0 && lines[0].contains(",");

        out.put("line_count", (long) ln);
        out.put("avg_line_len", avg);
        out.put("max_line_len", max);
        out.put("ratio_digit", rd);
        out.put("ratio_alpha", ra);
        out.put("ratio_symbol", rs);
        out.put("has_csv_header", hasCsv);
        return out;
    }

    private record GuardEval(boolean hasMap, String mapping, Boolean separated, String reason) {}

    @SuppressWarnings("unchecked")
    private GuardEval evalPseudonymization(Map<String, Object> extra) {
        if (extra == null) return new GuardEval(false, null, null, null);
        Object mapping = extra.get("mapping_locator");
        if (mapping == null) return new GuardEval(false, null, null, null);

        Map<String,Object> sep = (Map<String,Object>) extra.getOrDefault("separated_by", Map.of());
        boolean separated = List.of(
            Boolean.TRUE.equals(sep.get("different_account")),
            Boolean.TRUE.equals(sep.get("different_kms_key")),
            Boolean.TRUE.equals(sep.get("network_boundary"))
        ).stream().anyMatch(Boolean::booleanValue);

        String reason = separated ? "별도 계정/KMS/네트워크 분리 충족" : "분리 근거 부족";
        return new GuardEval(true, String.valueOf(mapping), separated, reason);
    }

    public static class BulkResult {
        public int created, updated, profiled, guarded;
    }

    @Transactional
    public BulkResult ingest(BulkIn in) {
        OffsetDateTime now = OffsetDateTime.now();
        BulkResult res = new BulkResult();

        for (AssetIn item : in.items()) {
            Map<String, Object> extra = mergeExtra(item);
            OffsetDateTime lastModified = parseIso((String) extra.get("last_modified"));
            String etag  = (String) extra.get("etag");
            String checksum = (String) extra.get("checksum");
            String version  = (String) extra.get("version");

            DataObject obj = dataRepo.findByLocator(item.locator()).orElse(null);
            if (obj != null) {
                // UPDATE
                obj.setSourceId(in.sourceId());
                obj.setObjectType(item.kind());
                obj.setBytes(item.bytes());
                obj.setExtra(extra);
                obj.setLastScanned(now);
                obj.setLastModified(lastModified);
                obj.setEtag(etag);
                obj.setChecksum(checksum);
                obj.setVersion(version);
                dataRepo.save(obj);
                res.updated++;
            } else {
                // INSERT
                obj = new DataObject();
                obj.setId(UUID.randomUUID().toString());
                obj.setSourceId(in.sourceId());
                obj.setObjectType(item.kind());
                obj.setLocator(item.locator());
                obj.setParentLocator(null);
                obj.setBytes(item.bytes());
                obj.setExtra(extra);
                obj.setFirstSeen(now);
                obj.setLastScanned(now);
                obj.setLastModified(lastModified);
                obj.setEtag(etag);
                obj.setChecksum(checksum);
                obj.setVersion(version);
                dataRepo.save(obj);
                res.created++;
            }

            // 프로파일
            Object sampleObj = extra.get("sample");
            if (sampleObj instanceof String sample && !sample.isEmpty()) {
                Map<String, Object> prof = profileText(sample);
                ObjectProfile p = new ObjectProfile();
                p.setObjectId(obj.getId());
                p.setBytes(Optional.ofNullable(item.bytes()).orElse(0L));
                p.setLineCount(((Number)prof.get("line_count")).longValue());
                p.setAvgLineLen(((Number)prof.get("avg_line_len")).doubleValue());
                p.setMaxLineLen(((Number)prof.get("max_line_len")).longValue());
                p.setRatioDigit(((Number)prof.get("ratio_digit")).doubleValue());
                p.setRatioAlpha(((Number)prof.get("ratio_alpha")).doubleValue());
                p.setRatioSymbol(((Number)prof.get("ratio_symbol")).doubleValue());
                p.setHasCsvHeader((Boolean) prof.get("has_csv_header"));
                p.setProfiledAt(now);
                profileRepo.save(p); // 동일 PK면 upsert
                res.profiled++;
            }

            // 가명처리 가드
            GuardEval ge = evalPseudonymization(extra);
            if (ge.hasMap) {
                PseudonymizationGuard g = new PseudonymizationGuard();
                g.setObjectId(obj.getId());
                g.setIsPseudonymized(true);
                g.setMappingLocator(ge.mapping);
                g.setSeparated(ge.separated);
                g.setSeparationReason(ge.reason);
                g.setCheckedAt(now);
                guardRepo.save(g); // 동일 PK면 upsert
                res.guarded++;
            }
        }
        return res;
    }

    @Transactional
    public CollectResp collect(MetaIn m) {
        OffsetDateTime now = OffsetDateTime.now();
        DataObject obj = new DataObject();
        obj.setId(UUID.randomUUID().toString());
        obj.setSourceId(m.sourceId());
        obj.setObjectType(m.objectType());
        obj.setLocator(m.locator());
        obj.setParentLocator(m.parentLocator());
        obj.setBytes(m.bytes());
        obj.setExtra(m.extra());
        obj.setFirstSeen(now);
        obj.setLastScanned(now);
        dataRepo.save(obj);
        return new CollectResp(obj.getId(), "stored");
    }
}
