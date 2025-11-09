# -*- coding: utf-8 -*-
"""
s3_id_matcher.py
RDS에서 추출한 ID를 Collector API의 Explorer를 통해 S3 파일에서 직접 검색
익명화 패턴 검증 기능 추가
"""

import json
import re
import requests
from typing import List, Dict, Any, Set, Optional
from pathlib import Path
from datetime import datetime, timezone


# 익명화 패턴 정의
ANONYMIZED_PATTERNS = {
    'zero': [0, '0', '00', '000'],
    'null': [None, 'null', 'NULL', 'Null', 'None', 'none', ''],
    'placeholder': [99, '99', 999, '999', 9999, '9999', -1, '-1'],
    'deleted': ['deleted', 'DELETED', 'Deleted', 'anonymized', 'ANONYMIZED', 'Anonymized', 'removed', 'REMOVED', 'Removed'],
}


class S3IDMatcher:
    """Collector API를 통해 S3에서 RDS ID 검색"""
    
    def __init__(self, collector_api: str):
        """
        Args:
            collector_api: Collector API 엔드포인트 (예: http://127.0.0.1:8000)
        """
        self.collector_api = collector_api.rstrip('/')
        self.session = requests.Session()
    
    def is_anonymized_row(self, row_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        행 데이터가 익명화되어 있는지 확인
        
        Args:
            row_data: CSV/JSON의 행 데이터
        
        Returns:
            {
                'is_anonymized': bool,
                'anonymized_fields': List[str],  # 익명화된 필드 목록
                'patterns_found': Dict[str, List[str]]  # 발견된 패턴 종류별 필드
            }
        """
        anonymized_fields = []
        patterns_found = {key: [] for key in ANONYMIZED_PATTERNS.keys()}
        
        for field_name, field_value in row_data.items():
            # id 필드는 검사하지 않음
            if field_name.lower().strip() == 'id':
                continue
            
            # 각 패턴 검사
            for pattern_type, pattern_values in ANONYMIZED_PATTERNS.items():
                matched = False
                
                # 직접 비교
                if field_value in pattern_values:
                    matched = True
                # 문자열인 경우 strip 후 비교
                elif isinstance(field_value, str):
                    field_value_stripped = field_value.strip()
                    # 대소문자 무시 비교 (문자열 패턴의 경우)
                    if field_value_stripped in pattern_values:
                        matched = True
                    else:
                        # 대소문자 무시하고 추가 비교
                        field_value_lower = field_value_stripped.lower()
                        for pattern in pattern_values:
                            if isinstance(pattern, str) and field_value_lower == pattern.lower():
                                matched = True
                                break
                
                if matched:
                    anonymized_fields.append(field_name)
                    patterns_found[pattern_type].append(field_name)
                    break
        
        # 익명화 판정: 모든 필드(id 제외)가 익명화 패턴과 일치해야 익명화된 것으로 간주
        total_fields = len([k for k in row_data.keys() if k.lower().strip() != 'id'])
        is_anonymized = total_fields > 0 and len(anonymized_fields) == total_fields
        
        return {
            'is_anonymized': is_anonymized,
            'anonymized_fields': list(set(anonymized_fields)),  # 중복 제거
            'patterns_found': {k: v for k, v in patterns_found.items() if v}  # 빈 리스트 제거
        }
    
    def get_s3_buckets(self) -> List[Dict[str, Any]]:
        """Collector에서 S3 버킷 목록 조회"""
        try:
            url = f"{self.collector_api}/api/s3-buckets"
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            buckets = response.json()
            
            if not isinstance(buckets, list):
                print(f"[Collector] 예상치 못한 응답 형식: {type(buckets)}")
                return []
            
            print(f"[Collector] S3 버킷 {len(buckets)}개 발견")
            for bucket in buckets:
                bucket_name = bucket.get('Name') or bucket.get('name')
                if bucket_name:
                    print(f"  - {bucket_name}")
            
            return buckets
        except Exception as e:
            print(f"[Collector] S3 버킷 조회 실패: {e}")
            return []
    
    def list_s3_files(
        self,
        bucket_name: str,
        prefix: str = "",
        max_keys: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        S3 버킷의 파일 목록 조회 (Explorer 사용)
        
        Args:
            bucket_name: S3 버킷명
            prefix: 접두사 필터 (선택)
            max_keys: 최대 조회 개수
        """
        try:
            url = f"{self.collector_api}/api/explorer/s3/{bucket_name}"
            params = {
                'prefix': prefix,
                'max_keys': max_keys
            }
            
            response = self.session.get(url, params=params, timeout=60)
            response.raise_for_status()
            result = response.json()
            
            files = []
            if isinstance(result, dict):
                files = result.get('objects', result.get('Contents', result.get('files', [])))
            elif isinstance(result, list):
                files = result
            
            print(f"[Collector] {bucket_name}: {len(files)}개 파일 발견")
            
            return files
        except Exception as e:
            print(f"[Collector] S3 파일 목록 조회 실패 ({bucket_name}): {e}")
            return []
    
    def download_s3_file(
        self,
        bucket_name: str,
        file_key: str
    ) -> Optional[str]:
        """
        S3 파일 내용 다운로드 (boto3 직접 사용)
        
        Args:
            bucket_name: S3 버킷명
            file_key: 파일 키
        
        Returns:
            파일 내용 (텍스트) 또는 None
        """
        try:
            import boto3
            
            s3_client = boto3.client('s3')
            response = s3_client.get_object(Bucket=bucket_name, Key=file_key)
            content = response['Body'].read()
            
            try:
                return content.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    return content.decode('latin-1', errors='ignore')
                except:
                    return content.decode('utf-8', errors='ignore')
                
        except Exception as e:
            print(f"[다운로드 실패] {bucket_name}/{file_key}: {e}")
            return None
    
    def extract_ids_from_text(
        self,
        text: str,
        target_ids: Set[int],
        file_key: str = ""
    ) -> Dict[str, Any]:
        """
        텍스트에서 특정 ID 패턴 추출 (익명화 검증 포함)
        CSV/JSON 파일의 경우 'id' 컬럼/키의 값만 검색하며,
        해당 행이 익명화되어 있으면 매칭에서 제외
        
        Args:
            text: 검색할 텍스트
            target_ids: 찾을 ID 집합
            file_key: 파일명 (확장자 확인용)
        
        Returns:
            {
                'found_ids': Set[int],
                'matches': [...],
                'anonymized_matches': [...]  # 익명화된 것으로 판정된 매칭
            }
        """
        if not text or not target_ids:
            return {'found_ids': set(), 'matches': [], 'anonymized_matches': []}
        
        found_ids = set()
        matches = []
        anonymized_matches = []
        
        # CSV 파일 처리
        if file_key.lower().endswith('.csv'):
            try:
                import csv
                from io import StringIO
                
                if text.startswith('\ufeff'):
                    text = text[1:]
                    print(f"    [BOM 제거] UTF-8 BOM 발견 및 제거")
                
                csv_reader = csv.DictReader(StringIO(text))
                fieldnames = csv_reader.fieldnames
                print(f"    [CSV 헤더] {fieldnames}")
                
                id_column = None
                if fieldnames:
                    for field in fieldnames:
                        if field and field.lower().strip() == 'id':
                            id_column = field
                            print(f"    [ID 컬럼 발견] '{id_column}'")
                            break
                
                if not id_column:
                    print(f"    [ID 컬럼 없음] CSV에 'id' 컬럼이 없어 검색 불가")
                    return {'found_ids': set(), 'matches': [], 'anonymized_matches': []}
                
                row_count = 0
                for row in csv_reader:
                    row_count += 1
                    id_value = row.get(id_column, '').strip()
                    
                    if id_value:
                        try:
                            num = int(id_value)
                            if num in target_ids:
                                # 익명화 검증
                                anon_check = self.is_anonymized_row(row)
                                
                                match_info = {
                                    'id': num,
                                    'row_data': dict(row),
                                    'row_number': row_count,
                                    'source': 'csv',
                                    'anonymization_check': anon_check
                                }
                                
                                if anon_check['is_anonymized']:
                                    anonymized_matches.append(match_info)
                                    print(f"    [익명화됨] row {row_count}: id={num} - 익명화 필드: {anon_check['anonymized_fields']}")
                                else:
                                    found_ids.add(num)
                                    matches.append(match_info)
                                    print(f"    [매칭] row {row_count}: id={num}")
                        except (ValueError, TypeError):
                            continue
                
                print(f"    [CSV 완료] {row_count}행 스캔")
                print(f"    - 유효 매칭: {len(found_ids)}개 ID")
                print(f"    - 익명화 제외: {len(anonymized_matches)}개")
                return {
                    'found_ids': found_ids,
                    'matches': matches,
                    'anonymized_matches': anonymized_matches
                }
                
            except Exception as e:
                print(f"    [CSV 파싱 실패] {e}")
                import traceback
                print(f"    {traceback.format_exc()}")
                return {'found_ids': set(), 'matches': [], 'anonymized_matches': []}
        
        # JSON 파일 처리
        elif file_key.lower().endswith('.json'):
            try:
                import json as json_lib
                
                try:
                    data = json_lib.loads(text)
                    print(f"    [JSON 파싱] 성공 (단일 JSON)")
                    is_jsonl = False
                except json_lib.JSONDecodeError:
                    print(f"    [JSON 파싱] JSONL 형식으로 재시도")
                    data = []
                    line_num = 0
                    for line in text.strip().split('\n'):
                        line = line.strip()
                        if line:
                            try:
                                line_num += 1
                                obj = json_lib.loads(line)
                                data.append(obj)
                            except json_lib.JSONDecodeError as e:
                                print(f"    [JSONL 라인 {line_num} 파싱 실패] {e}")
                                continue
                    
                    if not data:
                        print(f"    [JSON 파싱 실패] 일반 JSON도 JSONL도 아님")
                        return {'found_ids': set(), 'matches': [], 'anonymized_matches': []}
                    
                    print(f"    [JSONL 파싱] 성공 ({len(data)}개 라인)")
                    is_jsonl = True
                
                if isinstance(data, list):
                    print(f"    [JSON 구조] 배열 ({len(data)}개 항목)")
                    
                    for idx, item in enumerate(data):
                        if isinstance(item, dict) and 'id' in item:
                            try:
                                num = int(item['id'])
                                if num in target_ids:
                                    # 익명화 검증
                                    anon_check = self.is_anonymized_row(item)
                                    
                                    match_info = {
                                        'id': num,
                                        'row_data': item,
                                        'row_number': idx + 1,
                                        'source': 'jsonl' if is_jsonl else 'json_array',
                                        'anonymization_check': anon_check
                                    }
                                    
                                    if anon_check['is_anonymized']:
                                        anonymized_matches.append(match_info)
                                        print(f"    [익명화됨] index {idx}: id={num} - 익명화 필드: {anon_check['anonymized_fields']}")
                                    else:
                                        found_ids.add(num)
                                        matches.append(match_info)
                                        print(f"    [매칭] index {idx}: id={num}")
                            except (ValueError, TypeError, KeyError):
                                continue
                
                elif isinstance(data, dict):
                    print(f"    [JSON 구조] 단일 객체")
                    
                    if 'id' in data:
                        try:
                            num = int(data['id'])
                            if num in target_ids:
                                anon_check = self.is_anonymized_row(data)
                                
                                match_info = {
                                    'id': num,
                                    'row_data': data,
                                    'row_number': 1,
                                    'source': 'json_object',
                                    'anonymization_check': anon_check
                                }
                                
                                if anon_check['is_anonymized']:
                                    anonymized_matches.append(match_info)
                                    print(f"    [익명화됨] id={num} - 익명화 필드: {anon_check['anonymized_fields']}")
                                else:
                                    found_ids.add(num)
                                    matches.append(match_info)
                                    print(f"    [매칭] id={num}")
                        except (ValueError, TypeError):
                            pass
                    
                    for key, value in data.items():
                        if isinstance(value, list):
                            print(f"    [JSON 구조] '{key}' 키 내 배열 ({len(value)}개 항목)")
                            for idx, item in enumerate(value):
                                if isinstance(item, dict) and 'id' in item:
                                    try:
                                        num = int(item['id'])
                                        if num in target_ids:
                                            anon_check = self.is_anonymized_row(item)
                                            
                                            match_info = {
                                                'id': num,
                                                'row_data': item,
                                                'row_number': idx + 1,
                                                'source': f'json_nested[{key}]',
                                                'anonymization_check': anon_check
                                            }
                                            
                                            if anon_check['is_anonymized']:
                                                anonymized_matches.append(match_info)
                                                print(f"    [익명화됨] {key}[{idx}]: id={num} - 익명화 필드: {anon_check['anonymized_fields']}")
                                            else:
                                                found_ids.add(num)
                                                matches.append(match_info)
                                                print(f"    [매칭] {key}[{idx}]: id={num}")
                                    except (ValueError, TypeError):
                                        continue
                
                print(f"    [JSON 완료]")
                print(f"    - 유효 매칭: {len(found_ids)}개 ID")
                print(f"    - 익명화 제외: {len(anonymized_matches)}개")
                return {
                    'found_ids': found_ids,
                    'matches': matches,
                    'anonymized_matches': anonymized_matches
                }
                
            except Exception as e:
                print(f"    [JSON 처리 오류] {e}")
                import traceback
                print(f"    {traceback.format_exc()}")
                return {'found_ids': set(), 'matches': [], 'anonymized_matches': []}
        
        else:
            print(f"    [파일 형식] CSV/JSON이 아니므로 검색 불가")
            return {'found_ids': set(), 'matches': [], 'anonymized_matches': []}
    
    def search_id_in_file(
        self,
        bucket_name: str,
        file_key: str,
        target_ids: Set[int]
    ) -> Dict[str, Any]:
        """
        특정 S3 파일에서 ID 검색 (익명화 검증 포함)
        
        Args:
            bucket_name: S3 버킷명
            file_key: 파일 키
            target_ids: 찾을 ID 집합
        
        Returns:
            매칭 결과
        """
        content = self.download_s3_file(bucket_name, file_key)
        
        if not content:
            return {
                'bucket': bucket_name,
                'file_key': file_key,
                'status': 'download_failed',
                'found_ids': [],
                'matches': [],
                'anonymized_matches': []
            }
        
        result = self.extract_ids_from_text(content, target_ids, file_key)
        found_ids = result['found_ids']
        matches = result['matches']
        anonymized_matches = result.get('anonymized_matches', [])
        
        if not found_ids and not anonymized_matches:
            return {
                'bucket': bucket_name,
                'file_key': file_key,
                'status': 'no_match',
                'found_ids': [],
                'matches': [],
                'anonymized_matches': []
            }
        
        status = 'matched' if found_ids else 'anonymized_only'
        
        return {
            'bucket': bucket_name,
            'file_key': file_key,
            'file_size': len(content),
            'status': status,
            'found_ids': sorted(found_ids),
            'matches': matches,
            'anonymized_matches': anonymized_matches,
            'total_id_count': len(found_ids),
            'anonymized_id_count': len(anonymized_matches)
        }
    
    def scan_bucket(
        self,
        bucket_name: str,
        target_ids: Set[int],
        file_extensions: Optional[List[str]] = None,
        max_files: int = 10000
    ) -> Dict[str, Any]:
        """
        S3 버킷 전체에서 ID 검색 (익명화 검증 포함)
        
        Args:
            bucket_name: S3 버킷명
            target_ids: 찾을 ID 집합
            file_extensions: 검색할 파일 확장자 (None이면 전체)
            max_files: 최대 검색 파일 수
        
        Returns:
            버킷 스캔 결과
        """
        if not target_ids:
            return {
                'bucket': bucket_name,
                'status': 'no_target_ids',
                'matched_files': [],
                'anonymized_files': []
            }
        
        print(f"\n[S3 스캔] 버킷 {bucket_name} 검색 시작...")
        print(f"[검색 대상] {len(target_ids)}개 ID: {sorted(target_ids)}")
        
        files = self.list_s3_files(bucket_name, max_keys=max_files)
        
        if not files:
            return {
                'bucket': bucket_name,
                'status': 'no_files',
                'matched_files': [],
                'anonymized_files': []
            }
        
        if file_extensions:
            filtered_files = []
            for f in files:
                file_key = f.get('Key') or f.get('key') or f.get('name', '')
                if any(file_key.lower().endswith(ext.lower()) for ext in file_extensions):
                    filtered_files.append(f)
            
            print(f"[필터링] {len(files)}개 중 {len(filtered_files)}개 파일 선택 (확장자: {file_extensions})")
            files = filtered_files
        
        matched_files = []
        anonymized_files = []
        scanned_count = 0
        found_ids_total = set()
        anonymized_ids_total = set()
        
        for file_info in files[:max_files]:
            file_key = file_info.get('Key') or file_info.get('key') or file_info.get('name', '')
            file_size = file_info.get('Size') or file_info.get('size', 0)
            
            if not file_key:
                continue
            
            if file_size > 10 * 1024 * 1024:
                print(f"  [SKIP] {file_key} (파일 크기: {file_size/1024/1024:.2f}MB)")
                continue
            
            scanned_count += 1
            print(f"  [{scanned_count}/{min(len(files), max_files)}] 검색 중: {file_key}")
            
            result = self.search_id_in_file(
                bucket_name=bucket_name,
                file_key=file_key,
                target_ids=target_ids
            )
            
            if result['status'] == 'matched':
                matched_files.append(result)
                found_ids_total.update(result['found_ids'])
                print(f"    ✓ 발견: {len(result['found_ids'])}개 고유 ID - {sorted(result['found_ids'])}")
            
            if result.get('anonymized_matches'):
                anonymized_files.append(result)
                anonymized_ids = {m['id'] for m in result['anonymized_matches']}
                anonymized_ids_total.update(anonymized_ids)
                print(f"    ⚠ 익명화: {len(anonymized_ids)}개 ID - {sorted(anonymized_ids)}")
        
        print(f"\n[버킷 스캔 완료] {bucket_name}")
        print(f"  - 스캔한 파일: {scanned_count}개")
        print(f"  - 유효 매칭 파일: {len(matched_files)}개")
        print(f"  - 익명화 파일: {len(anonymized_files)}개")
        print(f"  - 발견된 고유 ID: {sorted(found_ids_total)}")
        print(f"  - 익명화된 ID: {sorted(anonymized_ids_total)}")
        
        return {
            'bucket': bucket_name,
            'status': 'completed',
            'scanned_files': scanned_count,
            'matched_files': matched_files,
            'anonymized_files': anonymized_files,
            'found_ids_summary': sorted(found_ids_total),
            'anonymized_ids_summary': sorted(anonymized_ids_total)
        }


def search_ids_in_s3_via_collector(
    collector_api: str,
    rds_ids: List[int],
    bucket_names: Optional[List[str]] = None,
    file_extensions: Optional[List[str]] = None,
    max_files_per_bucket: int = 10000
) -> Dict[str, Any]:
    """
    RDS ID를 Collector API를 통해 S3에서 검색 (익명화 검증 포함)
    """
    print("="*70)
    print("=== S3에서 RDS ID 검색 시작 (익명화 검증 포함) ===")
    print("="*70)
    print(f"\n[검색 설정]")
    print(f"  - Collector API: {collector_api}")
    print(f"  - 검색할 ID: {len(rds_ids)}개 - {rds_ids}")
    
    if not rds_ids:
        return {
            'error': '검색할 ID가 없습니다.',
            'matched_files': [],
            'anonymized_files': [],
            'summary': {
                'total_rds_ids': 0,
                'matched_ids_count': 0,
                'anonymized_ids_count': 0,
                'matched_files_count': 0
            }
        }
    
    matcher = S3IDMatcher(collector_api)
    target_ids = set(rds_ids)
    
    if bucket_names is None:
        buckets = matcher.get_s3_buckets()
        bucket_names = []
        for b in buckets:
            name = b.get('Name') or b.get('name')
            if name:
                bucket_names.append(name)
    
    if not bucket_names:
        print("[경고] 검색할 S3 버킷이 없습니다.")
        return {
            'error': 'S3 버킷을 찾을 수 없습니다.',
            'matched_files': [],
            'anonymized_files': [],
            'summary': {
                'total_rds_ids': len(rds_ids),
                'matched_ids_count': 0,
                'anonymized_ids_count': 0,
                'matched_files_count': 0
            }
        }
    
    print(f"\n[대상 버킷] {len(bucket_names)}개")
    for bucket in bucket_names:
        print(f"  - {bucket}")
    print()
    
    bucket_results = []
    all_found_ids = set()
    all_anonymized_ids = set()
    all_matched_files = []
    all_anonymized_files = []
    
    for bucket_name in bucket_names:
        result = matcher.scan_bucket(
            bucket_name=bucket_name,
            target_ids=target_ids,
            file_extensions=file_extensions,
            max_files=max_files_per_bucket
        )
        
        bucket_results.append(result)
        
        if result.get('found_ids_summary'):
            all_found_ids.update(result['found_ids_summary'])
        
        if result.get('anonymized_ids_summary'):
            all_anonymized_ids.update(result['anonymized_ids_summary'])
        
        if result.get('matched_files'):
            all_matched_files.extend(result['matched_files'])
        
        if result.get('anonymized_files'):
            all_anonymized_files.extend(result['anonymized_files'])
    
    not_found_ids = target_ids - all_found_ids - all_anonymized_ids
    
    print("\n" + "="*70)
    print("=== 검색 완료 ===")
    print("="*70)
    print(f"\n[결과 요약]")
    print(f"  - 검색한 ID: {len(rds_ids)}개")
    print(f"  - 발견된 ID (유효): {len(all_found_ids)}개")
    print(f"  - 익명화된 ID: {len(all_anonymized_ids)}개")
    print(f"  - 미발견 ID: {len(not_found_ids)}개")
    print(f"  - 유효 매칭 파일: {len(all_matched_files)}개")
    print(f"  - 익명화 파일: {len(all_anonymized_files)}개")
    
    if all_found_ids:
        print(f"\n[발견된 ID (유효)] {sorted(all_found_ids)}")
        print("  ⚠️  이 ID들은 S3에 익명화되지 않은 데이터가 존재합니다!")
    
    if all_anonymized_ids:
        print(f"\n[익명화된 ID] {sorted(all_anonymized_ids)}")
        print("  ✓ 이 ID들은 S3에서 익명화 처리되어 있습니다.")
    
    if not_found_ids:
        print(f"\n[미발견 ID] {sorted(not_found_ids)}")
        print("  ✓ 이 ID들은 S3에서 찾을 수 없습니다.")
    
    print()
    
    return {
        'scan_time': datetime.now(timezone.utc).isoformat(),
        'collector_api': collector_api,
        'rds_ids_checked': sorted(rds_ids),
        'found_ids': sorted(all_found_ids),
        'anonymized_ids': sorted(all_anonymized_ids),
        'not_found_ids': sorted(not_found_ids),
        'matched_files': all_matched_files,
        'anonymized_files': all_anonymized_files,
        'bucket_results': bucket_results,
        'summary': {
            'total_rds_ids': len(rds_ids),
            'matched_ids_count': len(all_found_ids),
            'anonymized_ids_count': len(all_anonymized_ids),
            'unmatched_ids_count': len(not_found_ids),
            'matched_files_count': len(all_matched_files),
            'anonymized_files_count': len(all_anonymized_files),
            'buckets_scanned': len(bucket_results),
            'status': 'found' if all_found_ids else ('anonymized_only' if all_anonymized_ids else 'not_found')
        }
    }