# -*- coding: utf-8 -*-
"""
engine_pii.py (AI 통합 + 상세 로그, 재시도 없음)
"""

from __future__ import annotations
from typing import List, Dict, Any
import requests

PII_MODEL_URL = "http://43.202.228.52:8900/infer"

# ============== 로그 유틸 ==============
def _truncate_text(text: str, max_len: int = 100) -> str:
    """텍스트를 잘라서 표시 (로그용)"""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def _log_analysis_result(text: str, merged: List[Dict[str, Any]]):
    """분석 결과를 상세하게 로그로 출력"""
    text_preview = _truncate_text(text, 80)
    
    if not merged:
        print(f"[AI 분석 완료] 텍스트: '{text_preview}' → PII 없음")
        return
    
    # 엔티티 타입별 집계
    entities_summary = {}
    for item in merged:
        entity_type = item.get("entity", "UNKNOWN")
        entities_summary[entity_type] = entities_summary.get(entity_type, 0) + 1
    
    summary_str = ", ".join([f"{k}:{v}" for k, v in entities_summary.items()])
    print(f"\n{'='*80}")
    print(f"[AI 분석 완료] 총 {len(merged)}건 탐지 ({summary_str})")
    print(f"원본 텍스트: '{text_preview}'")
    print(f"{'-'*80}")
    
    # 각 탐지 항목 상세 출력
    for idx, item in enumerate(merged, 1):
        entity_type = item.get("entity", "UNKNOWN")
        detected_text = item.get("text", "")
        score = item.get("score", 0.0)
        start = item.get("start", 0)
        end = item.get("end", 0)
        
        # 탐지된 텍스트 주변 컨텍스트 보여주기 (앞뒤 20자)
        context_start = max(0, start - 20)
        context_end = min(len(text), end + 20)
        context = text[context_start:context_end]
        
        # 컨텍스트에서 탐지된 부분 표시
        relative_start = start - context_start
        relative_end = end - context_start
        
        print(f"  [{idx}] {entity_type}")
        print(f"      탐지값: '{detected_text}'")
        print(f"      신뢰도: {score:.2f}")
        print(f"      위치: {start}~{end}")
        print(f"      컨텍스트: ...{context[:relative_start]}[{context[relative_start:relative_end]}]{context[relative_end:]}...")
    
    print(f"{'='*80}\n")


# ============== AI 분석 함수 ==============
def analyze_text(text: str) -> Dict[str, Any]:
    """
    AI 기반 PII API 사용 (재시도 없음)
    반환 형태:
    {"merged": [ {entity, start, end, text, score}, ... ] }
    """
    if not text:
        return {"merged": []}

    try:
        response = requests.post(
            PII_MODEL_URL,
            json={"text": text, "mask": False},
            timeout=1500,
        )
        response.raise_for_status()
        data = response.json()

        merged: List[Dict[str, Any]] = []
        for span in data.get("spans", []):
            merged.append({
                "entity": span.get("label"),
                "start": span.get("start"),
                "end": span.get("end"),
                "text": span.get("text"),
                "score": float(span.get("score", 0.0)),
            })

        merged = _dedupe_hits(merged)
        
        # 분석 결과 상세 로그 출력
        _log_analysis_result(text, merged)
        
        return {"merged": merged}

    except requests.exceptions.ConnectionError as e:
        print(f"[engine_pii] AI 분석 실패 (연결 오류): {e}")
        return {"merged": []}
    
    except requests.exceptions.Timeout as e:
        print(f"[engine_pii] AI 분석 실패 (타임아웃): {e}")
        return {"merged": []}
    
    except requests.exceptions.HTTPError as e:
        print(f"[engine_pii] AI 분석 실패 (HTTP 오류): {e}")
        return {"merged": []}
    
    except Exception as e:
        print(f"[engine_pii] AI 분석 실패: {e}")
        return {"merged": []}


def _dedupe_hits(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """중복 제거"""
    best = {}
    for h in hits:
        k = (h.get("entity"), h.get("start"), h.get("end"), h.get("text"))
        if k not in best:
            best[k] = h
    return list(best.values())


# 기존 코드와의 호환
def presidio_scan(text: str) -> List[Dict[str, Any]]:
    return analyze_text(text).get("merged", [])


def list_loaded_recognizers() -> List[Dict[str, Any]]:
    """AI 모델 정보 반환 (호환용)"""
    return [{
        "name": "AI_PII_Model",
        "langs": ["ko", "en"],
        "entities": ["NAME", "PHONE", "EMAIL", "ADDRESS", "DOB", "RRN_KR"]
    }]


if __name__ == "__main__":
    # 테스트
    test_text = "홍길동의 전화번호는 010-1234-5678이고, 이메일은 hong@example.com입니다."
    print(f"\n[테스트] 입력: {test_text}")
    result = analyze_text(test_text)
    print(f"\n[결과] {result}")
