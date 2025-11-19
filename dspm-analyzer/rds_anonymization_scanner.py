# -*- coding: utf-8 -*-
"""
rds_anonymization_scanner.py
RDS에서 익명화된 레코드를 탐지하고, 원본 데이터가 완전히 삭제되었는지 검증
"""

import os
import re
import json
import pymysql
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timezone
from pathlib import Path

# 익명화 패턴 정의
ANONYMIZED_PATTERNS = {
    'zero': [0, '0', '00', '000'],
    'null': [None, 'null', 'NULL', 'None'],
    'placeholder': [99, '99', 999, '999', 9999, '9999', -1, '-1'],
    'deleted': ['deleted', 'DELETED', 'anonymized', 'ANONYMIZED'],
}

# RDS 연결 설정 (환경변수 또는 기본값)
DEFAULT_RDS_CONFIG = {
    'host': os.getenv('RDS_HOST', 'localhost'),
    'port': int(os.getenv('RDS_PORT', '3306')),
    'user': os.getenv('RDS_USER', 'dspm'),
    'password': os.getenv('RDS_PASSWORD', 'dspm'),
    'database': os.getenv('RDS_DATABASE', 'dspm'),
}


class RDSAnonymizationScanner:
    """RDS 익명화 검증 스캐너"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or DEFAULT_RDS_CONFIG
        self.connection = None
        
    def connect(self):
        """RDS 연결"""
        try:
            self.connection = pymysql.connect(
                host=self.config['host'],
                port=self.config['port'],
                user=self.config['user'],
                password=self.config['password'],
                database=self.config['database'],
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
            print(f"[RDS] 연결 성공: {self.config['host']}:{self.config['port']}/{self.config['database']}")
            return True
        except Exception as e:
            print(f"[RDS] 연결 실패: {e}")
            return False
    
    def close(self):
        """연결 종료"""
        if self.connection:
            self.connection.close()
            print("[RDS] 연결 종료")
    
    def get_all_tables(self) -> List[str]:
        """데이터베이스의 모든 테이블 목록 조회"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SHOW TABLES")
                tables = [list(row.values())[0] for row in cursor.fetchall()]
                print(f"[RDS] 테이블 발견: {len(tables)}개")
                return tables
        except Exception as e:
            print(f"[RDS] 테이블 목록 조회 실패: {e}")
            return []
    
    def get_table_columns(self, table_name: str) -> List[Dict[str, str]]:
        """테이블의 컬럼 정보 조회"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(f"DESCRIBE `{table_name}`")
                columns = cursor.fetchall()
                return columns
        except Exception as e:
            print(f"[RDS] 테이블 {table_name} 컬럼 조회 실패: {e}")
            return []
    
    def is_anonymized_value(self, value: Any) -> bool:
        """값이 익명화된 값인지 판단"""
        for category, patterns in ANONYMIZED_PATTERNS.items():
            if value in patterns:
                return True
            # 문자열 비교 (대소문자 무시)
            if isinstance(value, str) and value.lower() in [str(p).lower() for p in patterns]:
                return True
        return False
    
    def find_anonymized_records(self, table_name: str, id_column: str = 'id') -> List[Dict[str, Any]]:
        """
        테이블에서 익명화된 레코드 탐지
        
        Args:
            table_name: 스캔할 테이블명
            id_column: ID 컬럼명 (기본: 'id')
        
        Returns:
            익명화된 레코드 리스트
        """
        anonymized_records = []
        
        try:
            # 테이블 컬럼 정보 조회
            columns = self.get_table_columns(table_name)
            if not columns:
                return anonymized_records
            
            # ID 컬럼 존재 여부 확인
            column_names = [col['Field'] for col in columns]
            if id_column not in column_names:
                print(f"[RDS] 테이블 {table_name}에 '{id_column}' 컬럼이 없음")
                return anonymized_records
            
            # 전체 레코드 조회 (제한: 최대 10,000건)
            with self.connection.cursor() as cursor:
                query = f"SELECT * FROM `{table_name}` LIMIT 10000"
                cursor.execute(query)
                rows = cursor.fetchall()
                
                print(f"[RDS] 테이블 {table_name}: {len(rows)}개 레코드 스캔 중...")
                
                for row in rows:
                    # ID 컬럼 외 다른 컬럼에서 익명화 패턴 탐지
                    anonymized_columns = {}
                    original_id = row.get(id_column)
                    
                    for col_name, col_value in row.items():
                        if col_name == id_column:
                            continue
                        
                        if self.is_anonymized_value(col_value):
                            anonymized_columns[col_name] = col_value
                    
                    # 익명화된 컬럼이 있으면 레코드 추가
                    if anonymized_columns:
                        anonymized_records.append({
                            'table': table_name,
                            'original_id': original_id,
                            'anonymized_columns': anonymized_columns,
                            'full_record': row
                        })
                
                if anonymized_records:
                    print(f"[RDS] 테이블 {table_name}: {len(anonymized_records)}개 익명화 레코드 발견")
        
        except Exception as e:
            print(f"[RDS] 테이블 {table_name} 스캔 실패: {e}")
        
        return anonymized_records
    
    def verify_data_deletion(self, original_ids: List[Any], search_tables: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        원본 ID가 다른 테이블에 존재하는지 검증
        
        Args:
            original_ids: 검증할 원본 ID 리스트
            search_tables: 검색할 테이블 리스트 (None이면 전체 테이블)
        
        Returns:
            검증 결과
        """
        if not original_ids:
            return {'status': 'ok', 'found': [], 'not_found': original_ids}
        
        # 검색할 테이블 결정
        if search_tables is None:
            search_tables = self.get_all_tables()
        
        found_records = []
        not_found_ids = set(original_ids)
        
        for table_name in search_tables:
            try:
                # 테이블 컬럼 조회
                columns = self.get_table_columns(table_name)
                column_names = [col['Field'] for col in columns]
                
                # ID 관련 컬럼 찾기 (id, user_id, customer_id 등)
                id_columns = [col for col in column_names if 'id' in col.lower()]
                
                if not id_columns:
                    continue
                
                # 각 ID 컬럼에서 검색
                for id_col in id_columns:
                    with self.connection.cursor() as cursor:
                        # IN 절로 한 번에 검색
                        placeholders = ','.join(['%s'] * len(original_ids))
                        query = f"SELECT * FROM `{table_name}` WHERE `{id_col}` IN ({placeholders})"
                        cursor.execute(query, original_ids)
                        results = cursor.fetchall()
                        
                        if results:
                            print(f"[RDS] 테이블 {table_name}.{id_col}에서 {len(results)}개 레코드 발견")
                            for result in results:
                                found_id = result.get(id_col)
                                found_records.append({
                                    'table': table_name,
                                    'id_column': id_col,
                                    'id_value': found_id,
                                    'record': result
                                })
                                not_found_ids.discard(found_id)
            
            except Exception as e:
                print(f"[RDS] 테이블 {table_name} 검색 실패: {e}")
                continue
        
        # 결과 판정
        status = 'violation' if found_records else 'ok'
        
        return {
            'status': status,
            'found': found_records,
            'not_found': list(not_found_ids),
            'summary': {
                'total_ids': len(original_ids),
                'found_count': len(found_records),
                'not_found_count': len(not_found_ids),
            }
        }
    
    def scan_and_verify(self, target_tables: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        전체 스캔 및 검증 프로세스
        
        1. 익명화된 레코드 탐지
        2. 원본 ID 추출
        3. 다른 테이블에서 존재 여부 확인
        
        Args:
            target_tables: 스캔할 테이블 리스트 (None이면 전체)
        
        Returns:
            전체 스캔 결과
        """
        print(f"\n{'='*70}")
        print("=== RDS 익명화 검증 스캔 시작 ===")
        print(f"{'='*70}\n")
        
        if not self.connect():
            return {'error': 'RDS 연결 실패'}
        
        try:
            # 1단계: 스캔 대상 테이블 결정
            if target_tables is None:
                target_tables = self.get_all_tables()
            
            print(f"[1단계] 스캔 대상 테이블: {len(target_tables)}개")
            print(f"  {', '.join(target_tables)}\n")
            
            # 2단계: 익명화된 레코드 탐지
            all_anonymized_records = []
            original_ids_set = set()
            
            for table_name in target_tables:
                records = self.find_anonymized_records(table_name)
                all_anonymized_records.extend(records)
                
                # 원본 ID 수집
                for record in records:
                    original_id = record.get('original_id')
                    if original_id and not self.is_anonymized_value(original_id):
                        original_ids_set.add(original_id)
            
            print(f"\n[2단계] 익명화 레코드 탐지 완료:")
            print(f"  - 총 {len(all_anonymized_records)}개 익명화 레코드")
            print(f"  - 추출된 원본 ID: {len(original_ids_set)}개\n")
            
            # 3단계: 데이터 삭제 검증
            if original_ids_set:
                verification_result = self.verify_data_deletion(
                    list(original_ids_set),
                    search_tables=target_tables
                )
                
                print(f"[3단계] 데이터 삭제 검증 완료:")
                print(f"  - 상태: {verification_result['status']}")
                print(f"  - 잔존 데이터: {verification_result['summary']['found_count']}개")
                print(f"  - 완전 삭제: {verification_result['summary']['not_found_count']}개\n")
            else:
                verification_result = {'status': 'ok', 'found': [], 'not_found': []}
                print(f"[3단계] 검증할 원본 ID가 없음\n")
            
            # 최종 결과
            result = {
                'scan_time': datetime.now(timezone.utc).isoformat(),
                'database': self.config['database'],
                'tables_scanned': target_tables,
                'anonymized_records': all_anonymized_records,
                'verification': verification_result,
                'summary': {
                    'total_anonymized': len(all_anonymized_records),
                    'unique_ids_checked': len(original_ids_set),
                    'residual_data_found': len(verification_result.get('found', [])),
                    'status': verification_result.get('status', 'ok')
                }
            }
            
            print(f"{'='*70}")
            print(f"=== 스캔 완료 ===")
            print(f"{'='*70}\n")
            
            return result
        
        finally:
            self.close()


def scan_rds_anonymization(config: Optional[Dict[str, Any]] = None, 
                          tables: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    RDS 익명화 검증 스캔 실행 (외부 호출용)
    
    Args:
        config: RDS 연결 설정
        tables: 스캔할 테이블 리스트
    
    Returns:
        스캔 결과
    """
    scanner = RDSAnonymizationScanner(config)
    return scanner.scan_and_verify(tables)


# CLI 테스트
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="RDS 익명화 검증 스캐너")
    parser.add_argument("--host", default="localhost", help="RDS 호스트")
    parser.add_argument("--port", type=int, default=3306, help="RDS 포트")
    parser.add_argument("--user", default="dspm", help="RDS 사용자")
    parser.add_argument("--password", default="dspm", help="RDS 비밀번호")
    parser.add_argument("--database", default="dspm", help="데이터베이스명")
    parser.add_argument("--tables", help="스캔할 테이블 (쉼표 구분)")
    parser.add_argument("--output", default="rds_anonymization_scan.json", help="출력 파일")
    
    args = parser.parse_args()
    
    config = {
        'host': args.host,
        'port': args.port,
        'user': args.user,
        'password': args.password,
        'database': args.database,
    }
    
    tables = args.tables.split(',') if args.tables else None
    
    result = scan_rds_anonymization(config, tables)
    
    # 결과 저장
    output_path = Path(args.output)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f"\n[출력] 결과 저장: {output_path.resolve()}")