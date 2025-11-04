# -*- coding: utf-8 -*-
"""
pdf_policy_parser_v6.py
공백 문제 해결 (금융거래 종료일로부 터 -> 금융거래종료일로부터)
"""

import re
import json
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

try:
    from pypdf import PdfReader
    PDF_AVAILABLE = True
except ImportError:
    try:
        import PyPDF2
        from PyPDF2 import PdfReader
        PDF_AVAILABLE = True
    except ImportError:
        PDF_AVAILABLE = False
        print("[warn] pypdf/PyPDF2 미설치. 'pip install pypdf' 실행 필요")


def extract_text_from_pdf(pdf_path: str) -> str:
    """PDF 파일에서 전체 텍스트 추출"""
    if not PDF_AVAILABLE:
        raise ImportError("pypdf/PyPDF2가 설치되지 않았습니다.")
    
    text_lines = []
    with open(pdf_path, 'rb') as f:
        reader = PdfReader(f)
        for page in reader.pages:
            text = page.extract_text()
            if text:
                text_lines.append(text)
    
    full_text = "\n".join(text_lines)
    print(f"[DEBUG] 전체 추출: {len(full_text)}자")
    return full_text


def clean_text(text: str) -> str:
    """텍스트 정제"""
    text = re.sub(r'[\r\t]+', ' ', text)
    text = re.sub(r'\s{2,}', ' ', text)
    return text.strip()


def normalize_spaces(text: str) -> str:
    """
    과도한 공백 정규화
    "금융거래 종료일로부 터" -> "금융거래종료일로부터"
    하지만 "제15조의2 3개월"은 "제15조의23개월"로 합치지 않음
    """
    # 먼저 여러 공백을 하나로
    text = re.sub(r'\s+', ' ', text)
    
    # 법령 조항과 숫자 사이는 공백 유지 (이미 하나로 줄어든 상태)
    text = re.sub(r'(제\d+조(?:의\d+)?)\s(\d+)', r'\1 \2', text)
    
    # 한글/영문 단어 내부의 공백 제거 (단, 위에서 보호한 부분 제외)
    # "제15조의2 3개월"은 이미 보호되었으므로 안전
    text = re.sub(r'(\w)\s+(\w)', r'\1\2', text)
    
    return text


def extract_purpose_retention_pairs(text: str) -> List[Dict[str, Any]]:
    """PDF에서 (목적, 보유기간) 쌍을 추출"""
    pairs = []
    
    # 방법1: 표 형태
    table_pairs = parse_table_format(text)
    if table_pairs:
        print(f"[DEBUG] 표 파싱: {len(table_pairs)}개")
        pairs.extend(table_pairs)
    
    # 방법2: 제2조 보유기간
    article2_pairs = parse_article2_format(text)
    if article2_pairs:
        print(f"[DEBUG] 제2조 파싱: {len(article2_pairs)}개")
        pairs.extend(article2_pairs)
    
    # 방법3: 제1조+제2조 결합
    if not table_pairs and not article2_pairs:
        combined_pairs = parse_article1_and_2_combined(text)
        if combined_pairs:
            print(f"[DEBUG] 제1조+제2조 결합: {len(combined_pairs)}개")
            pairs.extend(combined_pairs)
    
    return pairs


def parse_table_format(text: str) -> List[Dict[str, Any]]:
    """표 형태 파싱"""
    pairs = []
    
    # 헤더 찾기
    header_patterns = [
        r'구분\s+목적\s+항목\s+보유\s*기?간',
        r'목적\s+항목\s+보유\s*기?간',
        r'처리\s*목적\s+수집\s*항목\s+보유\s*기?간',
        r'항목\s+목적\s+보유\s*기?간',
        r'개인정보\s*항목\s+처리\s*목적\s+보유\s*기?간',
        r'항목\s+처리\s*목적\s+보관\s*기?간',
        r'수집\s*항목\s+(?:수집\s*)?목적\s+보유\s*기?간',
    ]
    
    # 모든 헤더 찾기 (여러 페이지에 걸쳐 있을 수 있음)
    all_headers = []
    for pattern in header_patterns:
        matches = list(re.finditer(pattern, text, re.UNICODE | re.IGNORECASE))
        all_headers.extend(matches)
    
    if not all_headers:
        print("[DEBUG] 표 헤더를 찾을 수 없습니다")
        return pairs
    
    # 시작 위치 순으로 정렬
    all_headers.sort(key=lambda m: m.start())
    print(f"[DEBUG] 표 헤더 발견: {len(all_headers)}개")
    for i, h in enumerate(all_headers):
        print(f"[DEBUG]   헤더 {i+1}: {h.group(0)} (위치: {h.start()})")
    
    # 첫 헤더부터 시작
    first_header = all_headers[0]
    table_start = first_header.end()
    table_text = text[table_start:]
    
    # 표 종료 패턴
    end_patterns = [
        r'\n\s*제\d+조\s*\([^)]*(?:제공|위탁|파기|권리|열람)[^)]*\)',  # 명확한 다른 조항
        r'\n\s*[■□▪▫●○◆◇]\s*개인정보',  # 불릿 포인트
        r'\n\s*\d+\.\s*개인정보',  # 번호 섹션
    ]
    
    best_end = len(table_text)
    for pattern in end_patterns:
        match = re.search(pattern, table_text)
        if match and match.start() < best_end:
            best_end = match.start()
            print(f"[DEBUG] 표 종료 패턴 발견: {table_text[match.start():match.start()+50]}")
    
    table_text = table_text[:best_end]
    
    print(f"[DEBUG] 표 영역 크기: {len(table_text)}자")
    print(f"[DEBUG] 표 영역 전체:\n{'='*70}\n{table_text}\n{'='*70}\n")
    
    # 중간에 나오는 헤더 반복 제거
    for header_match in all_headers[1:]:
        # 헤더 위치가 표 영역 내부에 있으면
        rel_pos = header_match.start() - first_header.end()
        if 0 < rel_pos < len(table_text):
            # 헤더 앞뒤 50자 정도 제거
            remove_start = max(0, rel_pos - 50)
            remove_end = min(len(table_text), rel_pos + 100)
            table_text = table_text[:remove_start] + '\n[페이지구분]\n' + table_text[remove_end:]
            print(f"[DEBUG] 중복 헤더 제거: 위치 {rel_pos}")
    
    # 행 단위 분리
    rows = split_table_rows(table_text)
    print(f"[DEBUG] 분리된 행 수: {len(rows)}개\n")
    
    for idx, row in enumerate(rows, 1):
        print(f"[DEBUG] === 행 {idx} 처리 시작 ===")
        print(f"[DEBUG] 원본: {row[:100]}...")
        
        parsed = parse_single_row(row)
        if parsed:
            print(f"[DEBUG] ✅ 파싱 성공")
            print(f"[DEBUG]   목적: {parsed['purpose'][:50]}")
            print(f"[DEBUG]   기간: {parsed['retention']}")
            pairs.append(parsed)
        else:
            print(f"[DEBUG] ❌ 파싱 실패")
        print()
    
    return pairs


def split_table_rows(table_text: str) -> List[str]:
    """표를 행 단위로 분리 (개선된 버전)"""
    rows = []
    current_row_lines = []
    
    lines = table_text.split('\n')
    
    for idx, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        
        # 페이지 번호나 회사명 같은 메타데이터 제거
        if re.match(r'^페이지\s+\d+\s*/\s*\d+', line):
            continue
        if re.match(r'^㈜', line):
            continue
        
        # 한 줄에 여러 행이 있는지 확인
        # 먼저 정규화를 해서 패턴 매칭이 잘 되도록
        normalized_line = normalize_spaces(line)
        split_lines = split_multi_row_line(normalized_line)
        
        # 분리되었으면 원본도 분리 (대략적으로)
        if len(split_lines) > 1:
            print(f"[DEBUG] 한 줄이 {len(split_lines)}개로 분리됨")
            # 정규화된 버전을 사용
            # 정규화된 버전을 사용
            for split_line in split_lines:
                # 새 행 판단 - 법령명(「 또는 『)으로 시작하는 경우만
                is_new_row = (
                    split_line.startswith('「') or 
                    split_line.startswith('『')
                )
                
                # 추가: 이전 줄이 보유기간으로 끝나고, 현재 줄이 법령명이 아니면서 긴 경우
                if not is_new_row and current_row_lines:
                    last_line = current_row_lines[-1] if current_row_lines else ''
                    # 이전 줄이 보유기간으로 끝나는지 확인
                    if re.search(r'(?:년|개월|일|파기)(?:까지)?\s*$', last_line):
                        # 현재 줄이 충분히 길고 (15자 이상), 목적처럼 보이면 새 행
                        if len(split_line) > 15 and not split_line.startswith(('구분', '페이지', '㈜')):
                            # 현재 줄에 "목적" 키워드가 있거나, 대문자로 시작하는 경우
                            if '목적' in split_line or re.match(r'^[A-Z가-힣]', split_line):
                                is_new_row = True
                
                if is_new_row and current_row_lines:
                    # 이전 행 저장
                    row_text = ' '.join(current_row_lines)
                    if len(row_text) > 10:
                        rows.append(row_text)
                    current_row_lines = [split_line]
                else:
                    current_row_lines.append(split_line)
        else:
            # 분리 안 됨 - 원본 사용
            split_line = line
            # 새 행 판단 - 법령명(「 또는 『)으로 시작하는 경우만
            is_new_row = (
                split_line.startswith('「') or 
                split_line.startswith('『')
            )
            
            # 추가: 이전 줄이 보유기간으로 끝나고, 현재 줄이 법령명이 아니면서 긴 경우
            if not is_new_row and current_row_lines:
                last_line = current_row_lines[-1] if current_row_lines else ''
                # 이전 줄이 보유기간으로 끝나는지 확인
                if re.search(r'(?:년|개월|일|파기)(?:까지)?\s*$', last_line):
                    # 현재 줄이 충분히 길고 (15자 이상), 목적처럼 보이면 새 행
                    if len(split_line) > 15 and not split_line.startswith(('구분', '페이지', '㈜')):
                        # 현재 줄에 "목적" 키워드가 있거나, 대문자로 시작하는 경우
                        if '목적' in split_line or re.match(r'^[A-Z가-힣]', split_line):
                            is_new_row = True
            
            if is_new_row and current_row_lines:
                # 이전 행 저장
                row_text = ' '.join(current_row_lines)
                if len(row_text) > 10:
                    rows.append(row_text)
                current_row_lines = [split_line]
            else:
                current_row_lines.append(split_line)
    
    # 마지막 행 저장
    if current_row_lines:
        row_text = ' '.join(current_row_lines)
        if len(row_text) > 10:
            rows.append(row_text)
    
    return rows


def split_multi_row_line(line: str) -> List[str]:
    """
    한 줄에 여러 행이 포함된 경우 분리
    예: "...3개월 통신사실확인자료 AI분석및내부모델학습목적 목적달성..."
    """
    # 보유기간 패턴들 (짧고 명확한 것 먼저)
    period_patterns = [
        r'\d{1,2}\s*개월(?!\w)',  # "3개월" (뒤에 한글이 안 붙음)
        r'\d{1,2}\s*일(?!\w)',
        r'금융거래\s*종료일로부터\s*\d{1,2}\s*년',
        r'\d{1,2}\s*년(?:까지)?(?!\w)',
        r'목적\s*달성.*?파기',  # 긴 복합 패턴
    ]
    
    # 보유기간이 여러 개 있는지 확인
    period_matches = []
    for pattern in period_patterns:
        matches = list(re.finditer(pattern, line, re.UNICODE))
        for match in matches:
            # 중복 제거 (같은 위치)
            if not any(abs(m.start() - match.start()) < 5 for m in period_matches):
                period_matches.append(match)
    
    # 시작 위치 순으로 정렬
    period_matches.sort(key=lambda m: m.start())
    
    print(f"[DEBUG]   한 줄에서 보유기간 {len(period_matches)}개 발견")
    for i, m in enumerate(period_matches):
        print(f"[DEBUG]     기간 {i+1}: '{m.group(0)}' (위치: {m.start()})")
    
    # 보유기간이 2개 이상이면 분리
    if len(period_matches) >= 2:
        lines = []
        
        for i in range(len(period_matches)):
            match = period_matches[i]
            
            # 현재 보유기간의 시작 지점 찾기
            if i == 0:
                start = 0  # 첫 번째는 줄 시작부터
            else:
                # 이전 보유기간 끝 + 항목 설명(약 100자) 후부터
                prev_end = period_matches[i-1].end()
                
                # 이전 보유기간 이후에 법령명(「)이나 키워드가 있으면 거기서 시작
                between = line[prev_end:match.start()]
                
                # "AI 분석", "고객", "통신" 등으로 시작하는 부분 찾기
                purpose_start = re.search(r'([A-Z가-힣]{2,})', between)
                if purpose_start:
                    start = prev_end + purpose_start.start()
                else:
                    start = prev_end + min(100, len(between))
            
            # 현재 보유기간 끝 지점
            end = match.end()
            
            # 항목 설명 포함 (최대 100자)
            if i < len(period_matches) - 1:
                next_start = period_matches[i+1].start()
                # 다음 보유기간 전까지 또는 100자 중 짧은 것
                between = line[end:next_start]
                item_end = re.search(r'([A-Z가-힣]{5,}|「)', between)
                if item_end:
                    end = end + item_end.start()
                else:
                    end = min(end + 100, next_start)
            else:
                # 마지막이면 끝까지
                end = len(line)
            
            segment = line[start:end].strip()
            if segment and len(segment) > 10:
                lines.append(segment)
                print(f"[DEBUG]     분리된 행 {i+1}: {segment[:60]}...")
        
        return lines if len(lines) > 1 else [line]
    
    return [line]


def parse_single_row(row_text: str) -> Optional[Dict[str, Any]]:
    """표의 한 행에서 목적과 보유기간 추출"""
    
    # 공백 정규화 (핵심!)
    normalized_text = normalize_spaces(row_text)
    
    print(f"[DEBUG]   정규화: {normalized_text[:100]}...")
    
    # 보유기간 패턴 (공백 유연하게)
    retention_patterns = [
        # 복합 패턴 (긴 것부터)
        r'목적달성(?:시|후)?(?:즉시)?파기(?:또는|혹은).{5,50}(?:보관|파기)',  # "목적달성 즉시 파기 또는 내부 방침에 따라..."
        r'금융거래종료일로부터\s*\d{1,2}\s*년(?:까지)?',
        r'금융거래\s*종료.*?부터\s*\d{1,2}\s*년',
        r'회원탈퇴시(?:까지)?',
        r'회원\s*탈퇴\s*시',
        r'서비스(?:제공|이용)완료시',
        r'동의철회시(?:까지)?',
        r'목적달성(?:시|후)?(?:즉시)?파기',
        r'인증서효력상실후\s*\d{1,2}\s*년',
        r'(?<![조의])\d{1,2}\s*년(?:까지)?',
        r'\d{1,2}\s*개월',
        r'\d{1,2}\s*일',
    ]
    
    retention = None
    retention_start = -1
    retention_end = -1
    
    # 보유기간 찾기
    for pattern in retention_patterns:
        matches = list(re.finditer(pattern, normalized_text, re.UNICODE))
        if matches:
            # 가장 마지막 매칭 선택
            last_match = matches[-1]
            retention = last_match.group(0).strip()
            retention_start = last_match.start()
            retention_end = last_match.end()
            print(f"[DEBUG]   보유기간 발견: '{retention}' (패턴: {pattern})")
            break
    
    if not retention:
        print(f"[DEBUG]   보유기간 찾기 실패")
        return None
    
    # 보유기간 앞부분과 뒷부분
    before_retention = normalized_text[:retention_start].strip()
    after_retention = normalized_text[retention_end:].strip()
    
    # 3컬럼 표 구조 감지: "법령명 + 보유기간 + 항목" 또는 "목적 + 보유기간 + 항목"
    is_three_column_format = False
    
    # 조건 1: 법령명으로 시작하고, 보유기간 뒤에 긴 텍스트가 있으면 3컬럼
    if before_retention.startswith('「') and len(after_retention) > 20:
        is_three_column_format = True
        print(f"[DEBUG]   3컬럼 표 형태 감지 (법령명)")
    
    # 조건 2: 목적이 짧고(목적 단독), 보유기간 뒤에 항목 설명이 길면 3컬럼
    elif len(before_retention) < 50 and len(after_retention) > 20:
        # "AI 분석 및 내부 모델 학습 목적" 같은 경우
        is_three_column_format = True
        print(f"[DEBUG]   3컬럼 표 형태 감지 (짧은 목적)")
    
    if is_three_column_format:
        # 3컬럼: 앞부분 = 목적, 보유기간 뒤 = 항목
        purpose = before_retention
        items = after_retention[:200]  # 항목은 너무 길 수 있으니 제한
        
        # 법령명이 있으면 정제, 없으면 그대로
        if purpose.startswith('「'):
            purpose = re.sub(r'^[「『][^」』]+[」』](?:제\d+조(?:의\d+)?)?', lambda m: m.group(0), purpose)
        purpose = clean_text(purpose)
        
        print(f"[DEBUG]   3컬럼 처리")
        print(f"[DEBUG]   목적: '{purpose[:50]}'")
        print(f"[DEBUG]   항목: '{items[:50]}'")
        
    else:
        # 4컬럼: 기존 로직
        # 항목 추출
        items_patterns = [
            r'고유식별정보\s*\([^)]+\)',
            r'고유식별정보',
            r'주민등록번호',
            r'여권번호',
            r'외국인등록번호',
            r'운전면허번호',
            r'실명확인증표[·・]서류',
        ]
        
        items = None
        before_items = before_retention
        
        for pattern in items_patterns:
            matches = list(re.finditer(pattern, before_retention, re.UNICODE))
            if matches:
                # 가장 마지막 항목 선택 (목적 뒤에 있는 경우가 많음)
                last_match = matches[-1]
                items = last_match.group(0).strip()
                before_items = before_retention[:last_match.start()].strip()
                print(f"[DEBUG]   항목 발견: '{items}'")
                break
        
        # 목적 추출
        purpose = before_items
        
        # 법령명 제거
        purpose = re.sub(r'^[「『][^」』]+[」』](?:제\d+조(?:의\d+)?)?', '', purpose)
        purpose = clean_text(purpose)
        
        print(f"[DEBUG]   목적 추출: '{purpose[:50]}'")
    
    # 유효성 검사
    if not purpose or len(purpose) < 3:
        print(f"[DEBUG]   목적이 너무 짧음: {len(purpose)}자")
        return None
    
    if re.match(r'^\d+$', purpose):
        return None
    
    return {
        'purpose': purpose,
        'retention': retention,
        'items': items,
    }


def parse_article2_format(text: str) -> List[Dict[str, Any]]:
    """제2조 파싱"""
    pairs = []
    
    pattern = r'제2조\s*\([^)]*보유[^)]*\)'
    matches = list(re.finditer(pattern, text, re.UNICODE))
    
    if not matches:
        return pairs
    
    print(f"[DEBUG] 제2조 발견: {len(matches)}개")
    
    best_section = None
    best_length = 0
    
    for match in matches:
        start = match.end()
        remaining_text = text[start:]
        next_article = re.search(r'제[3-9]조', remaining_text)
        
        if next_article:
            section_text = remaining_text[:next_article.start()]
        else:
            section_text = remaining_text[:1000]
        
        if len(section_text) > best_length:
            best_length = len(section_text)
            best_section = section_text
    
    if not best_section or best_length < 100:
        return pairs
    
    section_text = best_section
    
    # "- 목적: 기간" 패턴
    pattern1 = r'[-–—]\s*([^:：\n]{3,100})\s*[:：]\s*([^\n]{3,150})'
    matches1 = list(re.finditer(pattern1, section_text, re.UNICODE))
    
    for m in matches1:
        purpose = clean_text(m.group(1))
        retention = clean_text(m.group(2))
        retention = re.sub(r'\([^)]{10,}\)$', '', retention).strip()
        
        if is_valid_retention(retention) and len(purpose) >= 3:
            if not re.match(r'^(표시|광고|계약|대금|소비자)', purpose):
                pairs.append({
                    'purpose': purpose,
                    'retention': retention,
                    'items': None,
                })
    
    return pairs


def parse_article1_and_2_combined(text: str) -> List[Dict[str, Any]]:
    """제1조+제2조 결합"""
    pairs = []
    
    purposes = extract_purposes_from_article1(text)
    if not purposes:
        return pairs
    
    retentions = extract_retentions_from_article2(text)
    if not retentions:
        return pairs
    
    for purpose_item in purposes:
        best_match = None
        best_similarity = 0
        
        for retention_item in retentions:
            similarity = calculate_similarity(purpose_item['key'], retention_item['purpose_key'])
            
            if similarity > best_similarity:
                best_similarity = similarity
                best_match = retention_item
        
        if best_match and best_similarity > 0.3:
            pairs.append({
                'purpose': purpose_item['text'],
                'retention': best_match['retention'],
                'items': None,
            })
    
    return pairs


def extract_purposes_from_article1(text: str) -> List[Dict[str, str]]:
    """제1조에서 목적 추출"""
    purposes = []
    
    pattern = r'제1조\s*\([^)]*처리\s*목적[^)]*\)(.+?)(?=제\d+조|$)'
    match = re.search(pattern, text, re.DOTALL | re.UNICODE)
    
    if not match:
        return purposes
    
    section_text = match.group(1)
    
    bracket_pattern = r'\[([^\]]{3,50})\]'
    for m in re.finditer(bracket_pattern, section_text, re.UNICODE):
        purpose_text = m.group(1).strip()
        purpose_key = re.sub(r'\s+', '', purpose_text).lower()
        
        purposes.append({
            'text': purpose_text,
            'key': purpose_key,
        })
    
    return purposes


def extract_retentions_from_article2(text: str) -> List[Dict[str, str]]:
    """제2조에서 보유기간 추출"""
    retentions = []
    
    pattern = r'제2조\s*\([^)]*보유[^)]*\)(.+?)(?=제\d+조|$)'
    match = re.search(pattern, text, re.DOTALL | re.UNICODE)
    
    if not match:
        return retentions
    
    section_text = match.group(1)
    
    item_pattern = r'[-–—]\s*([^:：\n]{3,100})\s*[:：]\s*([^\n]{3,100})'
    
    for m in re.finditer(item_pattern, section_text, re.UNICODE):
        purpose = clean_text(m.group(1))
        retention = clean_text(m.group(2))
        
        if is_valid_retention(retention):
            purpose_key = re.sub(r'\s+', '', purpose).lower()
            retentions.append({
                'purpose': purpose,
                'purpose_key': purpose_key,
                'retention': retention,
            })
    
    return retentions


def calculate_similarity(text1: str, text2: str) -> float:
    """텍스트 유사도"""
    text1 = text1.lower().replace(' ', '')
    text2 = text2.lower().replace(' ', '')
    
    if text1 == text2:
        return 1.0
    
    if text1 in text2 or text2 in text1:
        min_len = min(len(text1), len(text2))
        max_len = max(len(text1), len(text2))
        return min_len / max_len
    
    set1 = set(text1)
    set2 = set(text2)
    
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    
    return intersection / union if union > 0 else 0


def is_valid_retention(text: str) -> bool:
    """유효한 보유기간인지 확인"""
    keywords = ['년', '개월', '일', '까지', '시', '파기', '완료', '탈퇴', '철회']
    return any(kw in text for kw in keywords) and len(text) >= 3


def compare_with_csv(pdf_pairs: List[Dict[str, Any]], csv_path: str) -> Dict[str, Any]:
    """PDF와 CSV 비교"""
    try:
        import sys
        import os
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        policies_dir = os.path.join(script_dir, 'policies')
        
        if policies_dir not in sys.path:
            sys.path.insert(0, policies_dir)
        
        from loader import load_policies
        csv_policies = load_policies(csv_path)
    except Exception as e:
        import traceback
        return {"error": f"CSV 로드 실패: {e}\n\n{traceback.format_exc()}"}
    
    results = {
        "total_pdf": len(pdf_pairs),
        "total_csv": len(csv_policies),
        "matched": [],
        "mismatched": [],
        "only_in_pdf": [],
        "only_in_csv": [],
    }
    
    csv_by_purpose = {}
    for csv_pol in csv_policies:
        purpose_key = (csv_pol.purpose or '').lower().strip()
        if purpose_key:
            if purpose_key not in csv_by_purpose:
                csv_by_purpose[purpose_key] = []
            csv_by_purpose[purpose_key].append(csv_pol)
    
    used_csv_purposes = set()
    
    for pdf_pair in pdf_pairs:
        pdf_purpose = pdf_pair['purpose'].lower().strip()
        pdf_retention = pdf_pair['retention'].strip()
        
        best_match = None
        best_similarity = 0
        
        for csv_purpose_key, csv_pols in csv_by_purpose.items():
            similarity = calculate_similarity(pdf_purpose, csv_purpose_key)
            
            if similarity > best_similarity and similarity > 0.5:
                best_similarity = similarity
                best_match = csv_pols[0]
                used_csv_purposes.add(csv_purpose_key)
        
        if best_match:
            csv_retention = (best_match.retention_raw or '').strip()
            
            if normalize_retention(pdf_retention) == normalize_retention(csv_retention):
                results["matched"].append({
                    "pdf_purpose": pdf_pair['purpose'],
                    "csv_purpose": best_match.purpose,
                    "retention": pdf_retention,
                    "csv_file_name": best_match.file_name,
                    "similarity": best_similarity,
                })
            else:
                results["mismatched"].append({
                    "pdf_purpose": pdf_pair['purpose'],
                    "csv_purpose": best_match.purpose,
                    "pdf_retention": pdf_retention,
                    "csv_retention": csv_retention,
                    "csv_file_name": best_match.file_name,
                    "similarity": best_similarity,
                })
        else:
            results["only_in_pdf"].append({
                "purpose": pdf_pair['purpose'],
                "retention": pdf_retention,
            })
    
    for csv_purpose_key, csv_pols in csv_by_purpose.items():
        if csv_purpose_key not in used_csv_purposes:
            for csv_pol in csv_pols:
                results["only_in_csv"].append({
                    "purpose": csv_pol.purpose,
                    "retention": csv_pol.retention_raw,
                    "file_name": csv_pol.file_name,
                })
    
    return results


def normalize_retention(retention: str) -> str:
    """
    보유기간 정규화 - 핵심 기간 정보만 추출
    예:
    - "5년" -> "5년"
    - "금융거래종료일로부터 5년까지" -> "5년"
    - "금융거래종료일로부터10년" -> "10년"
    - "3개월" -> "3개월"
    - "목적달성즉시파기" -> "즉시파기"
    """
    retention = retention.lower().strip()
    retention = re.sub(r'\s+', '', retention)
    
    # 패턴별 정규화
    # 1. "N년" 추출
    year_match = re.search(r'(\d{1,2})년', retention)
    if year_match:
        return f"{year_match.group(1)}년"
    
    # 2. "N개월" 추출
    month_match = re.search(r'(\d{1,2})개월', retention)
    if month_match:
        return f"{month_match.group(1)}개월"
    
    # 3. "N일" 추출
    day_match = re.search(r'(\d{1,2})일', retention)
    if day_match:
        return f"{day_match.group(1)}일"
    
    # 4. "즉시파기" 관련
    if '즉시파기' in retention or '즉시' in retention:
        return "즉시파기"
    
    # 5. "목적달성" 관련
    if '목적달성' in retention:
        return "목적달성시"
    
    # 6. "탈퇴시", "철회시" 등
    if '탈퇴' in retention:
        return "탈퇴시"
    if '철회' in retention:
        return "철회시"
    if '완료' in retention:
        return "완료시"
    
    # 그 외는 원본 반환
    return retention


def parse_policies_from_pdf(pdf_path: str) -> Dict[str, Any]:
    """PDF 파싱 메인"""
    text = extract_text_from_pdf(pdf_path)
    pairs = extract_purpose_retention_pairs(text)
    
    print(f"\n[DEBUG] 추출된 (목적, 기간) 쌍: {len(pairs)}개")
    
    return {
        "pairs": pairs,
        "total_count": len(pairs),
    }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="PDF 파싱 v6 (공백 문제 해결)")
    parser.add_argument("--pdf", required=True, help="PDF 파일 경로")
    parser.add_argument("--csv", help="CSV 파일 경로")
    parser.add_argument("--output", default="pdf_parsed_v6.json", help="출력 JSON")
    
    args = parser.parse_args()
    
    print(f"[*] PDF 파싱: {args.pdf}")
    result = parse_policies_from_pdf(args.pdf)
    
    print(f"\n{'='*70}")
    print(f"=== 파싱 결과 ===")
    print(f"{'='*70}")
    print(f"✅ 총 {result['total_count']}개의 (목적, 기간) 쌍 추출\n")
    
    for idx, pair in enumerate(result['pairs'][:20], 1):
        print(f"{idx}. 목적: {pair['purpose'][:60]}")
        print(f"   기간: {pair['retention']}")
        if pair.get('items'):
            print(f"   항목: {pair['items'][:50]}")
        print()
    
    if args.csv:
        print(f"\n[*] CSV 비교: {args.csv}")
        comparison = compare_with_csv(result['pairs'], args.csv)
        
        if 'error' in comparison:
            print(f"⚠️  {comparison['error']}")
        else:
            print(f"\n{'='*70}")
            print(f"=== 비교 결과 ===")
            print(f"{'='*70}")
            print(f"✅ 완전 일치: {len(comparison['matched'])}개")
            print(f"⚠️  불일치: {len(comparison['mismatched'])}개")
            print(f"📄 PDF에만: {len(comparison['only_in_pdf'])}개")
            print(f"📋 CSV에만: {len(comparison['only_in_csv'])}개")
            
            result['comparison'] = comparison
    
    output_path = Path(args.output)
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding='utf-8'
    )
    print(f"\n[ok] 결과 저장: {output_path.resolve()}")
