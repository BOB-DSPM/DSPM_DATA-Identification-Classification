# -*- coding: utf-8 -*-
"""
s3_id_matcher.py
RDS에서 추출한 ID를 Collector API를 통해 S3 파일에서 직접 검색
"""

import json
import re
import requests
from typing import List, Dict, Any, Set, Optional
from pathlib import Path
from datetime import datetime, timezone


class S3IDMatcher:
    """Collector API를 통해 S3에서 RDS ID 검색"""
    
    def __init__(self, collector_api: str):
        """
        Args:
            collector_api: Collector API 엔드포인트 (예: http://211.44.183.248:8000)
        """
        self.collector_api = collector_api.rstrip('/')
        self.session = requests.Session()
    
    def get_s3_buckets(self) -> List[Dict[str, Any]]:
        """Collector에서 S3 버킷 목록 조회"""
        try:
            url = f"{self.collector_api}/api/repositories"
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            repos = response.json()
            
            # S3 타입만 필터링
            s3_buckets = [r for r in repos if r.get('type') == 's3']
            
            print(f"[Collector] S3 버킷 {len(s3_buckets)}개 발견")
            for bucket in s3_buckets:
                print(f"  - {bucket.get('name', 'unknown')}")
            
            return s3_buckets
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
        S3 버킷의 파일 목록 조회
        
        Args:
            bucket_name: S3 버킷명
            prefix: 접두사 필터 (선택)
            max_keys: 최대 조회 개수
        """
        try:
            url = f"{self.collector_api}/api/repositories/s3/{bucket_name}/files"
            params = {
                'prefix': prefix,
                'max_keys': max_keys
            }
            
            response = self.session.get(url, params=params, timeout=60)
            response.raise_for_status()
            result = response.json()
            
            files = result.get('files', [])
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
        S3 파일 내용 다운로드
        
        Args:
            bucket_name: S3 버킷명
            file_key: 파일 키
        
        Returns:
            파일 내용 (텍스트) 또는 None
        """
        try:
            url = f"{self.collector_api}/api/repositories/s3/{bucket_name}/download"
            params = {'key': file_key}
            
            response = self.session.get(url, params=params, timeout=120)
            response.raise_for_status()
            
            # 텍스트 파일인 경우
            content_type = response.headers.get('content-type', '')
            if 'text' in content_type or 'json' in content_type or 'csv' in content_type:
                return response.text
            
            # 바이너리 파일은 텍스트로 디코딩 시도
            try:
                return response.content.decode('utf-8', errors='ignore')
            except:
                return response.content.decode('latin-1', errors='ignore')
                
        except Exception as e:
            print(f"[다운로드 실패] {bucket_name}/{file_key}: {e}")
            return None
    
    def extract_ids_from_text(
        self,
        text: str,
        target_ids: Set[int]
    ) -> Set[int]:
        """
        텍스트에서 특정 ID 패턴 추출
        
        Args:
            text: 검색할 텍스트
            target_ids: 찾을 ID 집합
        
        Returns:
            발견된 ID 집합
        """
        if not text or not target_ids:
            return set()
        
        found_ids = set()
        
        # 모든 숫자 패턴 추출
        numbers = re.findall(r'\b\d+\b', text)
        
        for num_str in numbers:
            try:
                num = int(num_str)
                if num in target_ids:
                    found_ids.add(num)
            except ValueError:
                continue
        
        return found_ids
    
    def search_id_in_file(
        self,
        bucket_name: str,
        file_key: str,
        target_ids: Set[int],
        context_length: int = 150
    ) -> Dict[str, Any]:
        """
        특정 S3 파일에서 ID 검색
        
        Args:
            bucket_name: S3 버킷명
            file_key: 파일 키
            target_ids: 찾을 ID 집합
            context_length: ID 주변 컨텍스트 길이
        
        Returns:
            매칭 결과
        """
        content = self.download_s3_file(bucket_name, file_key)
        
        if not content:
            return {
                'bucket': bucket_name,
                'file_key': file_key,
                'status': 'download_failed',
                'found_ids': []
            }
        
        # ID 추출
        found_ids = self.extract_ids_from_text(content, target_ids)
        
        if not found_ids:
            return {
                'bucket': bucket_name,
                'file_key': file_key,
                'status': 'no_match',
                'found_ids': []
            }
        
        # 각 ID의 컨텍스트 추출
        matches = []
        for found_id in found_ids:
            pattern = rf'\b{found_id}\b'
            for match in re.finditer(pattern, content):
                start = max(0, match.start() - context_length)
                end = min(len(content), match.end() + context_length)
                context = content[start:end]
                
                matches.append({
                    'id': found_id,
                    'position': match.start(),
                    'context': context,
                    'line_number': content[:match.start()].count('\n') + 1
                })
        
        return {
            'bucket': bucket_name,
            'file_key': file_key,
            'file_size': len(content),
            'status': 'matched',
            'found_ids': sorted(found_ids),
            'matches': matches,
            'total_occurrences': len(matches)
        }
    
    def scan_bucket(
        self,
        bucket_name: str,
        target_ids: Set[int],
        file_extensions: Optional[List[str]] = None,
        max_files: int = 100
    ) -> Dict[str, Any]:
        """
        S3 버킷 전체에서 ID 검색
        
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
                'matched_files': []
            }
        
        print(f"\n[S3 스캔] 버킷 {bucket_name} 검색 시작...")
        print(f"[검색 대상] {len(target_ids)}개 ID: {sorted(target_ids)}")
        
        # 파일 목록 조회
        files = self.list_s3_files(bucket_name, max_keys=max_files)
        
        if not files:
            return {
                'bucket': bucket_name,
                'status': 'no_files',
                'matched_files': []
            }
        
        # 파일 확장자 필터링
        if file_extensions:
            filtered_files = [
                f for f in files
                if any(f['key'].lower().endswith(ext.lower()) for ext in file_extensions)
            ]
            print(f"[필터링] {len(files)}개 중 {len(filtered_files)}개 파일 선택 (확장자: {file_extensions})")
            files = filtered_files
        
        # 각 파일 검색
        matched_files = []
        scanned_count = 0
        found_ids_total = set()
        
        for file_info in files[:max_files]:
            file_key = file_info.get('key', '')
            file_size = file_info.get('size', 0)
            
            # 너무 큰 파일은 스킵 (10MB 이상)
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
                print(f"    ✓ 발견: {len(result['found_ids'])}개 ID, {result['total_occurrences']}회 출현")
        
        print(f"\n[버킷 스캔 완료] {bucket_name}")
        print(f"  - 스캔한 파일: {scanned_count}개")
        print(f"  - 매칭된 파일: {len(matched_files)}개")
        print(f"  - 발견된 ID: {len(found_ids_total)}개")
        
        return {
            'bucket': bucket_name,
            'status': 'completed',
            'scanned_files': scanned_count,
            'matched_files': matched_files,
            'found_ids_summary': sorted(found_ids_total),
            'total_matches': sum(f['total_occurrences'] for f in matched_files)
        }


def search_ids_in_s3_via_collector(
    collector_api: str,
    rds_ids: List[int],
    bucket_names: Optional[List[str]] = None,
    file_extensions: Optional[List[str]] = None,
    max_files_per_bucket: int = 100
) -> Dict[str, Any]:
    """
    RDS ID를 Collector API를 통해 S3에서 검색
    
    Args:
        collector_api: Collector API 주소
        rds_ids: 검색할 RDS ID 리스트
        bucket_names: 검색할 S3 버킷 목록 (None이면 전체)
        file_extensions: 검색할 파일 확장자 (예: ['.csv', '.json', '.txt'])
        max_files_per_bucket: 버킷당 최대 검색 파일 수
    
    Returns:
        검색 결과
    
    예시:
        result = search_ids_in_s3_via_collector(
            collector_api="http://211.44.183.248:8000",
            rds_ids=[3, 8, 20, 26, 33, 43, 52],
            bucket_names=["my-data-bucket"],
            file_extensions=['.csv', '.json']
        )
    """
    print("="*70)
    print("=== S3에서 RDS ID 검색 시작 ===")
    print("="*70)
    print(f"\n[검색 설정]")
    print(f"  - Collector API: {collector_api}")
    print(f"  - 검색할 ID: {len(rds_ids)}개 - {rds_ids}")
    
    if not rds_ids:
        return {
            'error': '검색할 ID가 없습니다.',
            'matched_files': [],
            'summary': {
                'total_rds_ids': 0,
                'matched_ids_count': 0,
                'matched_files_count': 0
            }
        }
    
    matcher = S3IDMatcher(collector_api)
    target_ids = set(rds_ids)
    
    # S3 버킷 목록 조회
    if bucket_names is None:
        buckets = matcher.get_s3_buckets()
        bucket_names = [b['name'] for b in buckets]
    
    if not bucket_names:
        print("[경고] 검색할 S3 버킷이 없습니다.")
        return {
            'error': 'S3 버킷을 찾을 수 없습니다.',
            'matched_files': [],
            'summary': {
                'total_rds_ids': len(rds_ids),
                'matched_ids_count': 0,
                'matched_files_count': 0
            }
        }
    
    print(f"\n[대상 버킷] {len(bucket_names)}개")
    for bucket in bucket_names:
        print(f"  - {bucket}")
    print()
    
    # 각 버킷 스캔
    bucket_results = []
    all_found_ids = set()
    all_matched_files = []
    
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
        
        if result.get('matched_files'):
            all_matched_files.extend(result['matched_files'])
    
    # 최종 요약
    not_found_ids = target_ids - all_found_ids
    
    print("\n" + "="*70)
    print("=== 검색 완료 ===")
    print("="*70)
    print(f"\n[결과 요약]")
    print(f"  - 검색한 ID: {len(rds_ids)}개")
    print(f"  - 발견된 ID: {len(all_found_ids)}개")
    print(f"  - 미발견 ID: {len(not_found_ids)}개")
    print(f"  - 매칭된 파일: {len(all_matched_files)}개")
    
    if all_found_ids:
        print(f"\n[발견된 ID] {sorted(all_found_ids)}")
        print("  ⚠️  이 ID들은 S3에 데이터가 존재합니다!")
    
    if not_found_ids:
        print(f"\n[미발견 ID] {sorted(not_found_ids)}")
        print("  ✓ 이 ID들은 S3에서 찾을 수 없습니다.")
    
    print()
    
    return {
        'scan_time': datetime.now(timezone.utc).isoformat(),
        'collector_api': collector_api,
        'rds_ids_checked': sorted(rds_ids),
        'found_ids': sorted(all_found_ids),
        'not_found_ids': sorted(not_found_ids),
        'matched_files': all_matched_files,
        'bucket_results': bucket_results,
        'summary': {
            'total_rds_ids': len(rds_ids),
            'matched_ids_count': len(all_found_ids),
            'unmatched_ids_count': len(not_found_ids),
            'matched_files_count': len(all_matched_files),
            'buckets_scanned': len(bucket_results),
            'status': 'found' if all_found_ids else 'not_found'
        }
    }


def search_rds_scan_result_in_s3(
    collector_api: str,
    rds_scan_result_path: str,
    bucket_names: Optional[List[str]] = None,
    file_extensions: Optional[List[str]] = None,
    max_files_per_bucket: int = 100,
    output_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    RDS 스캔 결과 파일을 읽어서 S3에서 검색
    
    Args:
        collector_api: Collector API 주소
        rds_scan_result_path: RDS 스캔 결과 JSON 파일 경로
        bucket_names: 검색할 S3 버킷 목록 (None이면 전체)
        file_extensions: 검색할 파일 확장자
        max_files_per_bucket: 버킷당 최대 검색 파일 수
        output_path: 결과 저장 경로 (None이면 저장 안함)
    
    Returns:
        검색 결과
    """
    # RDS 스캔 결과 로드
    rds_result_path = Path(rds_scan_result_path)
    if not rds_result_path.exists():
        return {
            'error': f'RDS 스캔 결과 파일을 찾을 수 없습니다: {rds_scan_result_path}'
        }
    
    try:
        rds_result = json.loads(rds_result_path.read_text(encoding='utf-8'))
    except Exception as e:
        return {
            'error': f'RDS 스캔 결과 파일 읽기 실패: {e}'
        }
    
    # RDS 결과에서 원본 ID 추출
    target_ids = set()
    
    # 단일 인스턴스 결과인 경우
    if 'verification' in rds_result:
        results_list = [rds_result]
    # 여러 인스턴스 결과인 경우
    elif 'results' in rds_result:
        results_list = rds_result['results']
    else:
        return {'error': 'Invalid RDS scan result format'}
    
    # 모든 위반 ID 수집
    for result in results_list:
        verification = result.get('verification', {})
        found_records = verification.get('found', [])
        
        for record in found_records:
            original_id = record.get('original_id')
            if original_id and isinstance(original_id, (int, str)):
                try:
                    target_ids.add(int(original_id))
                except ValueError:
                    continue
    
    if not target_ids:
        print("[경고] RDS 스캔 결과에서 검증할 ID를 찾을 수 없습니다.")
        return {
            'error': 'RDS 스캔에서 위반 ID를 찾지 못했습니다.'
        }
    
    # S3 검색 실행
    result = search_ids_in_s3_via_collector(
        collector_api=collector_api,
        rds_ids=sorted(target_ids),
        bucket_names=bucket_names,
        file_extensions=file_extensions,
        max_files_per_bucket=max_files_per_bucket
    )
    
    # 결과 저장
    if output_path:
        output_file = Path(output_path)
        output_file.write_text(
            json.dumps(result, ensure_ascii=False, indent=2),
            encoding='utf-8'
        )
        print(f"\n[출력] 결과 저장: {output_file.resolve()}")
    
    return result


# CLI 테스트
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="RDS ID를 S3에서 검색 (Collector API 사용)")
    parser.add_argument("--collector", default="http://211.44.183.248:8000", help="Collector API 주소")
    
    # 검색 방법 1: ID 직접 입력
    parser.add_argument("--ids", help="검색할 ID (쉼표 구분, 예: 3,8,20,26)")
    
    # 검색 방법 2: RDS 스캔 결과 파일 사용
    parser.add_argument("--rds-result", help="RDS 스캔 결과 JSON 파일")
    
    # 공통 옵션
    parser.add_argument("--buckets", help="검색할 S3 버킷 (쉼표 구분, 미지정시 전체)")
    parser.add_argument("--extensions", help="파일 확장자 필터 (쉼표 구분, 예: .csv,.json)")
    parser.add_argument("--max-files", type=int, default=100, help="버킷당 최대 검색 파일 수")
    parser.add_argument("--output", default="s3_id_match_result.json", help="출력 파일")
    
    args = parser.parse_args()
    
    # 버킷 및 확장자 파싱
    bucket_list = args.buckets.split(',') if args.buckets else None
    ext_list = args.extensions.split(',') if args.extensions else None
    
    # 검색 실행
    if args.rds_result:
        # RDS 스캔 결과에서 ID 추출하여 검색
        result = search_rds_scan_result_in_s3(
            collector_api=args.collector,
            rds_scan_result_path=args.rds_result,
            bucket_names=bucket_list,
            file_extensions=ext_list,
            max_files_per_bucket=args.max_files,
            output_path=args.output
        )
    elif args.ids:
        # 직접 입력한 ID로 검색
        rds_ids = [int(id.strip()) for id in args.ids.split(',')]
        result = search_ids_in_s3_via_collector(
            collector_api=args.collector,
            rds_ids=rds_ids,
            bucket_names=bucket_list,
            file_extensions=ext_list,
            max_files_per_bucket=args.max_files
        )
        
        # 결과 저장
        if args.output:
            output_path = Path(args.output)
            output_path.write_text(
                json.dumps(result, ensure_ascii=False, indent=2),
                encoding='utf-8'
            )
            print(f"\n[출력] 결과 저장: {output_path.resolve()}")
    else:
        parser.error("--ids 또는 --rds-result 중 하나는 필수입니다.")