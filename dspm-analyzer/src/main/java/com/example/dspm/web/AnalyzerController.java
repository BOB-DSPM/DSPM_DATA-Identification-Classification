package com.example.dspm.web;

import com.example.dspm.repo.*;
import com.example.dspm.service.AnalyzerService;
import com.example.dspm.web.dto.*;
import com.example.dspm.domain.ObjectProfile;
import com.example.dspm.domain.PseudonymizationGuard;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.data.domain.PageRequest;

import java.util.*;

import jakarta.servlet.http.HttpServletRequest; 

@RestController
@RequestMapping
public class AnalyzerController {

    private final AnalyzerService service;
    private final ObjectProfileRepo profileRepo;
    private final PseudonymizationGuardRepo guardRepo;

    public AnalyzerController(AnalyzerService service, ObjectProfileRepo profileRepo, PseudonymizationGuardRepo guardRepo) {
        this.service = service;
        this.profileRepo = profileRepo;
        this.guardRepo = guardRepo;
    }

    @GetMapping("/health")
    public Map<String,Object> health() {
        return Map.of("ok", true);
    }

    // -------- Collector 벌크 수신 --------
    @PostMapping({"/api/assets:bulk", "/api/assets/save"})
    public Map<String,Object> ingest(@RequestBody BulkIn in) {
        AnalyzerService.BulkResult r = service.ingest(in);
        return Map.of(
            "ok", true,
            "created", r.created,
            "updated", r.updated,
            "profiled", r.profiled,
            "guarded", r.guarded
        );
    }

    // -------- 기존 개별 메타 수집 (테스트용) --------
    @PostMapping("/collect/meta")
    @ResponseStatus(HttpStatus.CREATED)
    public CollectResp collect(@RequestBody MetaIn in) {
        return service.collect(in);
    }

    // -------- 조회/리포트 API --------
    @GetMapping("/profiles/**")
    public Map<String,Object> getProfile(HttpServletRequest req) {  // ✅ 수정됨
        // /profiles/{locator:path} 지원: 전체 path에서 "/profiles/" 이후를 locator로 사용
        String uri = req.getRequestURI();
        String locator = uri.substring("/profiles/".length());
        ObjectProfile p = profileRepo.findByLocator(locator)
                .orElseThrow(() -> new org.springframework.web.server.ResponseStatusException(HttpStatus.NOT_FOUND, "profile not found"));

        Map<String,Object> out = new LinkedHashMap<>();
        out.put("locator", locator);
        out.put("object_id", p.getObjectId());
        out.put("bytes", p.getBytes());
        out.put("line_count", p.getLineCount());
        out.put("avg_line_len", p.getAvgLineLen());
        out.put("max_line_len", p.getMaxLineLen());
        out.put("ratio_digit", p.getRatioDigit());
        out.put("ratio_alpha", p.getRatioAlpha());
        out.put("ratio_symbol", p.getRatioSymbol());
        out.put("has_csv_header", p.getHasCsvHeader());
        out.put("profiled_at", p.getProfiledAt());
        return out;
    }

    @GetMapping("/guards/violations")
    public List<Map<String,Object>> violations(@RequestParam(name="limit", defaultValue="50") int limit) {
        var rows = guardRepo.findViolationsPaged(PageRequest.of(0, Math.min(limit, 200)));
        List<Map<String,Object>> list = new ArrayList<>();
        for (Object[] r : rows) {
            String locator = (String) r[0];
            var g = (PseudonymizationGuard) r[1];
            list.add(Map.of(
                "locator", locator,
                "mapping_locator", g.getMappingLocator(),
                "separated", g.getSeparated(),
                "separation_reason", g.getSeparationReason(),
                "checked_at", g.getCheckedAt()
            ));
        }
        return list;
    }

    @GetMapping("/guards/status")
    public Map<String,Object> guardStatus() {
        long total = guardRepo.countTotal();
        long ok = guardRepo.countOk();
        long bad = total - ok;
        return Map.of(
            "pseudonymized_total", total,
            "separated_ok", ok,
            "separated_missing", bad
        );
    }
}
