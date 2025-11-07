# -*- coding: utf-8 -*-
"""
rds_collector_based_scanner_v2.py
개선된 Collector API 기반 RDS 익명화 검증 스캐너
- RDS 메타데이터 자동 수집
- 간소화된 연결 설정 (password만 입력)
"""

import os
import json
import requests
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timezone
from pathlib import Path

# 익명화 패턴 정의
ANONYMIZED_PATTERNS = {
    'zero': [0, '0', '00', '000'],
    'null': [None, 'null', 'NULL', 'None', ''],
    'placeholder': [99, '99', 999, '999', 9999, '9999', -1, '-1'],
    'deleted': ['deleted', 'DELETED', 'anonymized', 'ANONYMIZED', 'removed', 'REMOVED'],
}


class CollectorBasedRDSScanner:
    """Collector API 기반 RDS 익명화 검증 스캐너 (v2 - 자동 메타데이터 수집)"""
    
    def __init__(self, collector_api: str, default_user: str = "madeit", default_password: str = "madeit1022!"):
        self.collector_api = collector_api.rstrip('/')
        self.session = requests.Session()
        self.rds_metadata_cache: Dict[str, Dict[str, Any]] = {}  # RDS 메타데이터 캐시
        self.default_user = default_user
        self.default_password = default_password
    
    def get_rds_instances(self) -> List[Dict[str, Any]]:
        """Collector에서 RDS 인스턴스 목록 조회 및 캐싱"""
        try:
            url = f"{self.collector_api}/api/rds-instances"
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            # API 응답이 객체일 경우 rds_instances 키 확인
            if isinstance(data, dict):
                instances = data.get('rds_instances', data.get('instances', []))
                # 그래도 배열이 아니면 전체 데이터를 배열로 감싸기
                if not isinstance(instances, list):
                    instances = [data] if data else []
            else:
                instances = data if isinstance(data, list) else []
            
            print(f"[Collector] RDS 인스턴스 {len(instances)}개 발견")
            
            # 메타데이터 캐싱 - 실제 API 응답 구조에 맞게 파싱
            for inst in instances:
                # 두 가지 필드명 형식 모두 지원 (CamelCase와 snake_case)
                db_id = inst.get('DBInstanceIdentifier') or inst.get('db_instance_identifier')
                
                # Endpoint는 객체일 수도, 분리된 필드일 수도 있음
                endpoint_data = inst.get('Endpoint', {})
                endpoint = endpoint_data.get('Address') if endpoint_data else inst.get('endpoint_address')
                port = endpoint_data.get('Port') if endpoint_data else inst.get('endpoint_port', 5432)
                
                engine = inst.get('Engine') or inst.get('engine', 'postgres')
                db_name = inst.get('DBName') or inst.get('db_name') or 'postgres'
                status = inst.get('DBInstanceStatus') or inst.get('status')
                
                if db_id and endpoint:
                    self.rds_metadata_cache[db_id] = {
                        'endpoint': endpoint,
                        'port': port,
                        'engine': engine,
                        'db_name': db_name,
                        'status': status
                    }
                    
                    print(f"  - {db_id} ({endpoint}:{port})")
                else:
                    print(f"  [Warning] 인스턴스 정보 불완전: db_id={db_id}, endpoint={endpoint}")
            
            return instances
        except Exception as e:
            print(f"[Collector] RDS 인스턴스 조회 실패: {e}")
            return []
    
    def get_rds_connection_info(self, db_identifier: str) -> Dict[str, Any]:
        """
        RDS 연결 정보 자동 조회
        캐시에 없으면 Collector에서 가져옴
        """
        if db_identifier not in self.rds_metadata_cache:
            # 캐시에 없으면 전체 목록 다시 조회
            self.get_rds_instances()
        
        return self.rds_metadata_cache.get(db_identifier, {})
    
    def get_rds_detail(self, db_identifier: str) -> Dict[str, Any]:
        """특정 RDS 인스턴스의 상세 정보 조회"""
        try:
            url = f"{self.collector_api}/api/repositories/rds/{db_identifier}"
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[Collector] RDS 상세 조회 실패 ({db_identifier}): {e}")
            return {}
    
    def explore_rds_tables(
        self,
        db_identifier: str,
        table_name: Optional[str] = None,
        limit: int = 50,
        custom_config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Collector의 RDS Explorer로 테이블 데이터 조회 (간소화 버전)
        
        Args:
            db_identifier: RDS 인스턴스 ID
            table_name: 특정 테이블명 (None이면 전체 테이블 목록)
            limit: 조회할 행 개수
            custom_config: 커스텀 설정 (없으면 자동으로 메타데이터 + 기본값 사용)
        """
        try:
            # 자동으로 메타데이터 가져오기
            conn_info = self.get_rds_connection_info(db_identifier)
            
            if not conn_info or not conn_info.get('endpoint'):
                return {'error': f'RDS 인스턴스 {db_identifier}의 메타데이터를 찾을 수 없습니다'}
            
            # 기본 설정 + 커스텀 설정 병합
            config = {
                'endpoint': conn_info['endpoint'],
                'port': conn_info.get('port', 5432),
                'db_name': conn_info.get('db_name', 'postgres'),
                'user': self.default_user,
                'password': self.default_password,
            }
            
            if custom_config:
                config.update(custom_config)
            
            # Collector API 호출
            url = f"{self.collector_api}/api/explorer/rds/{db_identifier}"
            params = {
                'endpoint': config['endpoint'],
                'port': config['port'],
                'db_name': config['db_name'],
                'user': config['user'],
                'password': config['password'],
                'limit': limit
            }
            
            if table_name:
                params['table_name'] = table_name
            
            response = self.session.get(url, params=params, timeout=60)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[Collector] RDS 탐색 실패 ({db_identifier}/{table_name}): {e}")
            return {'error': str(e)}
    
    def is_anonymized_value(self, value: Any) -> bool:
        """값이 익명화된 값인지 판단"""
        for category, patterns in ANONYMIZED_PATTERNS.items():
            if value in patterns:
                return True
            # 문자열 비교 (대소문자 무시)
            if isinstance(value, str):
                v_lower = value.lower().strip()
                if v_lower in [str(p).lower() for p in patterns]:
                    return True
        return False
    
    def find_anonymized_records(
        self,
        records: List[Dict[str, Any]],
        id_column: str = 'id'
    ) -> List[Dict[str, Any]]:
        """
        레코드 리스트에서 익명화된 레코드 탐지
        
        Args:
            records: 레코드 리스트
            id_column: ID 컬럼명
        
        Returns:
            익명화된 레코드 리스트
        """
        anonymized_records = []
        
        for record in records:
            anonymized_columns = {}
            original_id = record.get(id_column)
            
            # ID 컬럼 외 다른 컬럼에서 익명화 패턴 탐지
            for col_name, col_value in record.items():
                if col_name == id_column:
                    continue
                
                if self.is_anonymized_value(col_value):
                    anonymized_columns[col_name] = col_value
            
            # 익명화된 컬럼이 있으면 레코드 추가
            if anonymized_columns:
                anonymized_records.append({
                    'original_id': original_id,
                    'anonymized_columns': anonymized_columns,
                    'full_record': record
                })
        
        return anonymized_records
    
    def verify_data_deletion(
        self,
        original_ids: List[Any],
        db_identifier: str,
        all_tables: List[str],
        custom_config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        원본 ID가 다른 테이블에 존재하는지 검증 (간소화 버전)
        
        Args:
            original_ids: 검증할 원본 ID 리스트
            db_identifier: RDS 인스턴스 ID
            all_tables: 검색할 테이블 리스트
            custom_config: 커스텀 DB 설정
        """
        if not original_ids:
            return {'status': 'ok', 'found': [], 'not_found': original_ids}
        
        found_records = []
        not_found_ids = set(original_ids)
        
        print(f"\n[검증] {len(original_ids)}개 ID의 잔존 데이터 확인 중...")
        
        for table_name in all_tables:
            try:
                # 테이블 데이터 조회 (최대 200건)
                table_data = self.explore_rds_tables(
                    db_identifier=db_identifier,
                    table_name=table_name,
                    limit=200,
                    custom_config=custom_config
                )
                
                if 'error' in table_data:
                    continue
                
                # 응답이 리스트일 수도, 딕셔너리일 수도 있음
                if isinstance(table_data, dict):
                    records = table_data.get('data', [])
                elif isinstance(table_data, list):
                    records = table_data
                else:
                    continue
                
                if not records:
                    continue
                
                # 첫 번째 레코드에서 ID 관련 컬럼 찾기
                first_record = records[0] if records else {}
                id_columns = [col for col in first_record.keys() if 'id' in col.lower()]
                
                if not id_columns:
                    continue
                
                # 각 ID 컬럼에서 검색
                for id_col in id_columns:
                    for record in records:
                        record_id = record.get(id_col)
                        
                        # 원본 ID 리스트에 있는지 확인
                        if record_id in original_ids:
                            found_records.append({
                                'table': table_name,
                                'id_column': id_col,
                                'id_value': record_id,
                                'record': record
                            })
                            
                            # 찾은 ID는 not_found에서 제거
                            not_found_ids.discard(record_id)
                            
                            print(f"  ⚠️  잔존 데이터 발견: {table_name}.{id_col} = {record_id}")
            
            except Exception as e:
                print(f"  [Error] {table_name} 검증 중 오류: {e}")
                continue
        
        status = 'violation' if found_records else 'ok'
        
        result = {
            'status': status,
            'found': found_records,
            'not_found': list(not_found_ids),
            'summary': {
                'found_count': len(found_records),
                'not_found_count': len(not_found_ids),
                'total_checked': len(original_ids)
            }
        }
        
        return result
    
    def scan_rds_instance(
        self,
        db_identifier: str,
        target_tables: Optional[List[str]] = None,
        custom_config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        단일 RDS 인스턴스 스캔 (간소화 버전 - 자동 메타데이터 활용)
        
        Args:
            db_identifier: RDS 인스턴스 ID
            target_tables: 스캔할 테이블 리스트 (None=전체)
            custom_config: 커스텀 DB 연결 설정 (password 등)
        """
        print(f"\n{'='*70}")
        print(f"=== RDS 익명화 검증 스캔 시작: {db_identifier} ===")
        print(f"{'='*70}\n")
        
        # 1단계: 연결 정보 자동 수집
        conn_info = self.get_rds_connection_info(db_identifier)
        
        if not conn_info or not conn_info.get('endpoint'):
            return {
                'error': f'RDS 인스턴스 {db_identifier}의 메타데이터를 찾을 수 없습니다',
                'db_identifier': db_identifier
            }
        
        endpoint = conn_info['endpoint']
        
        print(f"[1단계] RDS 연결 정보 (자동 수집)")
        print(f"  - Endpoint: {endpoint}")
        print(f"  - Port: {conn_info.get('port')}")
        print(f"  - Engine: {conn_info.get('engine')}")
        print(f"  - DB Name: {conn_info.get('db_name')}")
        print(f"  - User: {custom_config.get('user', self.default_user) if custom_config else self.default_user}")
        
        # 테이블 목록 조회
        if not target_tables:
            print(f"\n[1단계] 전체 테이블 목록 조회 중...")
            tables_data = self.explore_rds_tables(
                db_identifier=db_identifier,
                custom_config=custom_config
            )
            
            # 응답이 리스트일 수도, 딕셔너리일 수도 있음
            if isinstance(tables_data, dict):
                if 'error' in tables_data:
                    return {
                        'error': f'테이블 목록 조회 실패: {tables_data["error"]}',
                        'db_identifier': db_identifier,
                        'endpoint': endpoint
                    }
                target_tables = tables_data.get('tables', [])
            elif isinstance(tables_data, list):
                # 응답이 직접 테이블 목록 배열인 경우
                target_tables = tables_data
            else:
                return {
                    'error': f'예상치 못한 응답 형식: {type(tables_data)}',
                    'db_identifier': db_identifier,
                    'endpoint': endpoint
                }
            
            # 테이블 목록이 딕셔너리 배열인 경우 테이블 이름만 추출
            if target_tables and isinstance(target_tables[0], dict):
                # [{"table": "users"}, ...] → ["users", ...]
                extracted_tables = []
                for t in target_tables:
                    # 다양한 키 이름 시도
                    table_name = (t.get('table') or t.get('table_name') or 
                                 t.get('name') or t.get('tablename') or 
                                 t.get('Table') or t.get('TABLE_NAME'))
                    if table_name:
                        extracted_tables.append(table_name)
                    else:
                        print(f"  [Warning] 테이블 이름을 찾을 수 없음: {t}")
                target_tables = extracted_tables
            
            if not target_tables:
                return {
                    'error': '테이블을 찾을 수 없습니다',
                    'db_identifier': db_identifier,
                    'endpoint': endpoint
                }
        
        print(f"[1단계] 스캔 대상 테이블: {len(target_tables)}개")
        print(f"  {', '.join(target_tables[:10])}{'...' if len(target_tables) > 10 else ''}\n")
        
        # 2단계: 각 테이블에서 익명화 레코드 탐지
        all_anonymized_records = []
        original_ids_set = set()
        
        for table_name in target_tables:
            print(f"[2단계] 테이블 {table_name} 스캔 중...")
            
            table_data = self.explore_rds_tables(
                db_identifier=db_identifier,
                table_name=table_name,
                limit=200,
                custom_config=custom_config
            )
            
            if 'error' in table_data:
                print(f"  ⚠️  스캔 실패: {table_data.get('error')}")
                continue
            
            # 응답이 리스트일 수도, 딕셔너리일 수도 있음
            if isinstance(table_data, dict):
                records = table_data.get('data', [])
            elif isinstance(table_data, list):
                # 응답이 직접 데이터 배열인 경우
                records = table_data
            else:
                print(f"  ⚠️  예상치 못한 응답 형식: {type(table_data)}")
                continue
            
            if not records:
                print(f"  → 데이터 없음")
                continue
            
            # 익명화 레코드 탐지
            anonymized = self.find_anonymized_records(records)
            
            if anonymized:
                print(f"  → 익명화 레코드 {len(anonymized)}개 발견")
                for anon_rec in anonymized:
                    anon_rec['table'] = table_name
                    all_anonymized_records.append(anon_rec)
                    
                    # 원본 ID 수집
                    original_id = anon_rec.get('original_id')
                    if original_id and not self.is_anonymized_value(original_id):
                        original_ids_set.add(original_id)
            else:
                print(f"  → 익명화 레코드 없음")
        
        print(f"\n[2단계 완료] 이 {len(all_anonymized_records)}개 익명화 레코드 발견")
        print(f"             추출된 원본 ID: {len(original_ids_set)}개\n")
        
        # 3단계: 데이터 삭제 검증
        if original_ids_set:
            verification_result = self.verify_data_deletion(
                original_ids=list(original_ids_set),
                db_identifier=db_identifier,
                all_tables=target_tables,
                custom_config=custom_config
            )
            
            print(f"\n[3단계 완료] 검증 상태: {verification_result['status']}")
            print(f"             잔존 데이터: {verification_result['summary']['found_count']}개")
            print(f"             완전 삭제: {verification_result['summary']['not_found_count']}개\n")
        else:
            verification_result = {'status': 'ok', 'found': [], 'not_found': []}
            print(f"\n[3단계] 검증할 원본 ID가 없음\n")
        
        # 최종 결과
        result = {
            'scan_time': datetime.now(timezone.utc).isoformat(),
            'db_identifier': db_identifier,
            'endpoint': endpoint,
            'connection_info': conn_info,
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
    
    def scan_all_rds_instances(
        self,
        db_identifiers: Optional[List[str]] = None,
        custom_configs: Optional[Dict[str, Dict[str, Any]]] = None,
        target_tables: Optional[Dict[str, List[str]]] = None
    ) -> Dict[str, Any]:
        """
        모든 RDS 인스턴스 스캔 (간소화 버전)
        
        Args:
            db_identifiers: 스캔할 RDS ID 리스트 (None=전체)
            custom_configs: {db_identifier: {password, ...}} 커스텀 설정
            target_tables: {db_identifier: [table_names]}
        """
        # RDS 인스턴스 목록 조회 및 캐싱
        instances = self.get_rds_instances()
        
        if not instances:
            return {'error': 'RDS 인스턴스를 찾을 수 없습니다'}
        
        # 스캔할 인스턴스 필터링
        if db_identifiers:
            filtered_instances = []
            for inst in instances:
                db_id = inst.get('DBInstanceIdentifier') or inst.get('db_instance_identifier')
                if db_id in db_identifiers:
                    filtered_instances.append(inst)
            instances = filtered_instances
        
        all_results = []
        
        for instance in instances:
            db_id = instance.get('DBInstanceIdentifier') or instance.get('db_instance_identifier')
            
            if not db_id:
                print(f"[Skip] 인스턴스 ID를 찾을 수 없습니다: {instance}")
                continue
            
            # 해당 인스턴스의 커스텀 설정
            custom_config = custom_configs.get(db_id) if custom_configs else None
            
            # 해당 인스턴스의 대상 테이블
            tables = target_tables.get(db_id) if target_tables else None
            
            # 스캔 실행
            result = self.scan_rds_instance(
                db_identifier=db_id,
                target_tables=tables,
                custom_config=custom_config
            )
            
            all_results.append(result)
        
        # 전체 요약
        total_anonymized = sum(r['summary']['total_anonymized'] for r in all_results if 'summary' in r)
        total_violations = sum(r['summary']['residual_data_found'] for r in all_results if 'summary' in r)
        
        return {
            'scan_time': datetime.now(timezone.utc).isoformat(),
            'collector_api': self.collector_api,
            'instances_scanned': len(all_results),
            'results': all_results,
            'summary': {
                'total_anonymized': total_anonymized,
                'total_violations': total_violations,
                'status': 'violation' if total_violations > 0 else 'ok'
            }
        }


# 외부 호출용 함수 (간소화 버전)
def scan_rds_via_collector_v2(
    collector_api: str,
    db_identifiers: Optional[List[str]] = None,
    passwords: Optional[Dict[str, str]] = None,
    target_tables: Optional[Dict[str, List[str]]] = None,
    default_user: str = "madeit",
    default_password: str = "madeit1022!"
) -> Dict[str, Any]:
    """
    Collector API를 통한 RDS 익명화 검증 스캔 (v2 - 간소화)
    
    Args:
        collector_api: Collector API 주소
        db_identifiers: 스캔할 RDS ID 리스트 (None=전체)
        passwords: {db_identifier: password} 각 인스턴스별 비밀번호 (선택)
        target_tables: {db_identifier: [table_names]} (선택)
        default_user: 기본 사용자명
        default_password: 기본 비밀번호
    
    예시:
        # 가장 간단한 사용 (모든 RDS, 기본 계정)
        result = scan_rds_via_collector_v2("http://collector-api")
        
        # 특정 RDS만, 커스텀 비밀번호
        result = scan_rds_via_collector_v2(
            "http://collector-api",
            db_identifiers=["my-rds-1", "my-rds-2"],
            passwords={"my-rds-1": "password1", "my-rds-2": "password2"}
        )
    """
    scanner = CollectorBasedRDSScanner(collector_api, default_user, default_password)
    
    # passwords를 custom_configs로 변환
    custom_configs = None
    if passwords:
        custom_configs = {
            db_id: {'password': pwd}
            for db_id, pwd in passwords.items()
        }
    
    return scanner.scan_all_rds_instances(db_identifiers, custom_configs, target_tables)


# CLI 테스트
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Collector 기반 RDS 익명화 스캐너 v2")
    parser.add_argument("--collector", default="http://43.202.228.52:8000", help="Collector API 주소")
    parser.add_argument("--db-ids", help="스캔할 RDS ID (쉼표 구분, 없으면 전체)")
    parser.add_argument("--user", default="madeit", help="기본 사용자명")
    parser.add_argument("--password", default="madeit1022!", help="기본 비밀번호")
    parser.add_argument("--output", default="rds_collector_scan_v2.json", help="출력 파일")
    
    args = parser.parse_args()
    
    db_ids = args.db_ids.split(',') if args.db_ids else None
    
    result = scan_rds_via_collector_v2(
        collector_api=args.collector,
        db_identifiers=db_ids,
        default_user=args.user,
        default_password=args.password
    )
    
    # 결과 저장
    output_path = Path(args.output)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f"\n[출력] 결과 저장: {output_path.resolve()}")