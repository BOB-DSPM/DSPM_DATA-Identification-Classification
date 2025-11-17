#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_rds_collect_and_scan.py
RDS 데이터 수집 + 익명화 검증 + 보유기간 스캔을 한 번에 실행
"""

import os
import sys
import json
import argparse
import requests
from pathlib import Path
from typing import Dict, Any, Optional

SAGE_HOST = os.getenv("SAGE_HOST", "43.202.228.52")

DEFAULT_ANALYZER_HOST = f"http://{SAGE_HOST}:9000"
DEFAULT_COLLECTOR_HOST = f"http://{SAGE_HOST}:8000"


DEFAULT_RDS_CONFIG = {
    'host': os.getenv('RDS_HOST', 'localhost'),
    'port': int(os.getenv('RDS_PORT', '3306')),
    'user': os.getenv('RDS_USER', 'dspm'),
    'password': os.getenv('RDS_PASSWORD', 'dspm'),
    'database': os.getenv('RDS_DATABASE', 'dspm'),
}


def call_rds_anonymization_scan(
    analyzer_host: str,
    rds_config: Dict[str, Any],
    tables: Optional[list] = None,
    collector_api: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyzer API를 호출하여 RDS 익명화 검증 스캔 실행
    
    Args:
        analyzer_host: Analyzer 서버 주소 (예: http://127.0.0.1:9000)
        rds_config: RDS 연결 설정
        tables: 스캔할 테이블 리스트
        collector_api: Collector API 주소 (선택)
    
    Returns:
        스캔 결과
    """
    url = f"{analyzer_host.rstrip('/')}/api/scan/rds-anonymization"
    
    payload = {
        'host': rds_config['host'],
        'port': rds_config['port'],
        'user': rds_config['user'],
        'password': rds_config['password'],
        'database': rds_config['database'],
        'tables': tables,
        'collector_api': collector_api,
    }
    
    print(f"\n[실행] RDS 익명화 검증 스캔 API 호출")
    print(f"  - Analyzer: {url}")
    print(f"  - RDS: {rds_config['host']}:{rds_config['port']}/{rds_config['database']}")
    if collector_api:
        print(f"  - Collector: {collector_api}")
    if tables:
        print(f"  - 대상 테이블: {', '.join(tables)}")
    else:
        print(f"  - 대상 테이블: 전체")
    
    try:
        response = requests.post(url, json=payload, timeout=300)
        response.raise_for_status()
        result = response.json()
        
        if result.get('ok'):
            print(f"\n[성공] RDS 익명화 검증 스캔 완료")
            print(f"  - 익명화 레코드: {result['scan_result']['summary']['total_anonymized']}개")
            print(f"  - 잔존 데이터: {result['scan_result']['summary']['residual_data_found']}개")
            print(f"  - 상태: {result['scan_result']['summary']['status']}")
            
            if result.get('combined_report'):
                print(f"  - 리포트: {result['combined_report']}")
        else:
            print(f"\n[실패] {result.get('error', '알 수 없는 오류')}")
        
        return result
    
    except requests.exceptions.RequestException as e:
        print(f"\n[오류] API 호출 실패: {e}")
        return {'ok': False, 'error': str(e)}


def call_collector_only(
    analyzer_host: str,
    collector_api: str,
    only_detected: bool = True
) -> Dict[str, Any]:
    """
    기존 Collector API만 호출 (보유기간 스캔)
    
    Args:
        analyzer_host: Analyzer 서버 주소
        collector_api: Collector API 주소
        only_detected: 탐지된 항목만 출력
    
    Returns:
        수집 결과
    """
    url = f"{analyzer_host.rstrip('/')}/api/collect"
    
    payload = {
        'collector_api': collector_api,
        'services': [],  # 전체 리소스
        'only_detected': only_detected,
    }
    
    print(f"\n[실행] Collector API 호출 (보유기간 스캔)")
    print(f"  - Collector: {collector_api}")
    
    try:
        response = requests.post(url, json=payload, timeout=300)
        response.raise_for_status()
        result = response.json()
        
        if result.get('ok'):
            print(f"\n[성공] 데이터 수집 완료")
            print(f"  - 결과 파일: {result.get('results_front')}")
        else:
            print(f"\n[실패] {result.get('error', '알 수 없는 오류')}")
        
        return result
    
    except requests.exceptions.RequestException as e:
        print(f"\n[오류] API 호출 실패: {e}")
        return {'ok': False, 'error': str(e)}


def main():
    parser = argparse.ArgumentParser(
        description="RDS 익명화 검증 + 보유기간 스캔 통합 실행"
    )
    
    # 모드 선택
    parser.add_argument(
        "--mode",
        choices=['rds', 'collector', 'both'],
        default='both',
        help="실행 모드: rds(익명화 검증만), collector(보유기간만), both(둘 다)"
    )
    
    # Analyzer/Collector 설정
    parser.add_argument("--analyzer", default=DEFAULT_ANALYZER_HOST, help="Analyzer 서버 주소")
    parser.add_argument("--collector", default=DEFAULT_COLLECTOR_HOST, help="Collector API 주소")
    
    # RDS 설정
    parser.add_argument("--rds-host", default=DEFAULT_RDS_CONFIG['host'], help="RDS 호스트")
    parser.add_argument("--rds-port", type=int, default=DEFAULT_RDS_CONFIG['port'], help="RDS 포트")
    parser.add_argument("--rds-user", default=DEFAULT_RDS_CONFIG['user'], help="RDS 사용자")
    parser.add_argument("--rds-password", default=DEFAULT_RDS_CONFIG['password'], help="RDS 비밀번호")
    parser.add_argument("--rds-database", default=DEFAULT_RDS_CONFIG['database'], help="데이터베이스명")
    parser.add_argument("--tables", help="스캔할 테이블 (쉼표 구분)")
    
    # 출력 설정
    parser.add_argument("--output", default="rds_scan_result.json", help="결과 저장 파일")
    
    args = parser.parse_args()
    
    # RDS 설정
    rds_config = {
        'host': args.rds_host,
        'port': args.rds_port,
        'user': args.rds_user,
        'password': args.rds_password,
        'database': args.rds_database,
    }
    
    tables = args.tables.split(',') if args.tables else None
    
    # 실행
    results = {}
    
    if args.mode in ['rds', 'both']:
        # RDS 익명화 검증 스캔 (Collector 연동 포함)
        collector_api = args.collector if args.mode == 'both' else None
        
        rds_result = call_rds_anonymization_scan(
            analyzer_host=args.analyzer,
            rds_config=rds_config,
            tables=tables,
            collector_api=collector_api
        )
        results['rds_scan'] = rds_result
    
    elif args.mode == 'collector':
        # Collector만 실행
        collector_result = call_collector_only(
            analyzer_host=args.analyzer,
            collector_api=args.collector
        )
        results['collector_scan'] = collector_result
    
    # 결과 저장
    output_path = Path(args.output)
    output_path.write_text(
        json.dumps(results, ensure_ascii=False, indent=2),
        encoding='utf-8'
    )
    
    print(f"\n{'='*70}")
    print(f"[완료] 결과 저장: {output_path.resolve()}")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()