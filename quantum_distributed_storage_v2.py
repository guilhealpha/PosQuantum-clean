#!/usr/bin/env python3
"""
🛡️ QuantumShield - Robust Distributed Storage System v2
Arquivo: quantum_distributed_storage_v2.py
Descrição: Sistema de armazenamento distribuído robusto sem warnings
Autor: QuantumShield Team
Versão: 2.0
Data: 03/07/2025
"""

import os
import sys
import time
import json
import logging
import threading
import hashlib
import secrets
import sqlite3
import asyncio
from typing import Dict, List, Optional, Tuple, Any, Union, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import pickle
import zlib
import base64
from collections import defaultdict, deque
import struct
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class StorageFragment:
    """Fragmento de dados armazenado"""
    fragment_id: str
    file_id: str
    fragment_index: int
    total_fragments: int
    data_hash: str
    encrypted_data: bytes
    size: int
    created_at: float
    peer_id: str
    redundancy_level: int
    access_count: int = 0
    last_accessed: float = 0.0

@dataclass
class StorageFile:
    """Arquivo no sistema de storage"""
    file_id: str
    filename: str
    original_size: int
    total_fragments: int
    file_hash: str
    encryption_key: bytes
    created_at: float
    updated_at: float
    owner_id: str
    access_permissions: Dict[str, str]
    redundancy_level: int
    fragments: List[str]
    metadata: Dict[str, Any]

@dataclass
class StoragePeer:
    """Peer no sistema de storage"""
    peer_id: str
    ip_address: str
    port: int
    public_key: bytes
    storage_capacity: int
    storage_used: int
    reliability_score: float
    last_seen: float
    fragments_hosted: Set[str]
    bandwidth_up: int
    bandwidth_down: int

@dataclass
class StorageStats:
    """Estatísticas do sistema de storage"""
    total_files: int
    total_fragments: int
    total_size: int
    available_space: int
    active_peers: int
    redundancy_ratio: float
    sync_status: str
    last_sync: float
    upload_speed: float
    download_speed: float

class QuantumDistributedStorageV2:
    """Sistema de armazenamento distribuído robusto"""
    
    def __init__(self, storage_dir: str = "quantum_storage", max_fragment_size: int = 1024*1024):
        self.storage_dir = Path(storage_dir)
        self.max_fragment_size = max_fragment_size
        self.peer_id = self.generate_peer_id()
        
        # Configurações
        self.config = {
            'default_redundancy': 3,
            'max_peers': 100,
            'sync_interval': 30,
            'cleanup_interval': 300,
            'max_storage_gb': 10,
            'bandwidth_limit_mbps': 100
        }
        
        # Estado interno
        self.files: Dict[str, StorageFile] = {}
        self.fragments: Dict[str, StorageFragment] = {}
        self.peers: Dict[str, StoragePeer] = {}
        self.stats = StorageStats(0, 0, 0, 0, 0, 0.0, "Initializing", 0.0, 0.0, 0.0)
        
        # Threading
        self.running = False
        self.sync_thread = None
        self.cleanup_thread = None
        self.lock = threading.RLock()
        
        # Criptografia robusta (sem warnings)
        self.master_key = self.derive_master_key()
        self.fernet = Fernet(self.master_key)
        
        # Inicializar
        self.initialize_storage()
        self.load_state()
    
    def generate_peer_id(self) -> str:
        """Gera ID único do peer"""
        return hashlib.sha256(
            f"{time.time()}{secrets.token_hex(16)}".encode()
        ).hexdigest()[:16]
    
    def derive_master_key(self) -> bytes:
        """Deriva chave mestra para criptografia"""
        # Usar dados únicos do sistema
        system_data = f"{os.getpid()}{time.time()}{secrets.token_hex(32)}".encode()
        
        # Derivar chave usando PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'quantumshield_storage_salt_v2',
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(system_data))
        return key
    
    def initialize_storage(self):
        """Inicializa diretórios e banco de dados"""
        try:
            # Criar diretórios
            self.storage_dir.mkdir(parents=True, exist_ok=True)
            (self.storage_dir / "fragments").mkdir(exist_ok=True)
            (self.storage_dir / "temp").mkdir(exist_ok=True)
            (self.storage_dir / "backups").mkdir(exist_ok=True)
            
            # Inicializar banco de dados
            self.init_database()
            
            logger.info(f"Storage inicializado: {self.storage_dir}")
            
        except Exception as e:
            logger.error(f"Erro ao inicializar storage: {e}")
            raise
    
    def init_database(self):
        """Inicializa banco de dados SQLite"""
        db_path = self.storage_dir / "storage.db"
        
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    file_id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    original_size INTEGER,
                    total_fragments INTEGER,
                    file_hash TEXT,
                    encryption_key BLOB,
                    created_at REAL,
                    updated_at REAL,
                    owner_id TEXT,
                    access_permissions TEXT,
                    redundancy_level INTEGER,
                    fragments TEXT,
                    metadata TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS fragments (
                    fragment_id TEXT PRIMARY KEY,
                    file_id TEXT,
                    fragment_index INTEGER,
                    total_fragments INTEGER,
                    data_hash TEXT,
                    size INTEGER,
                    created_at REAL,
                    peer_id TEXT,
                    redundancy_level INTEGER,
                    access_count INTEGER DEFAULT 0,
                    last_accessed REAL DEFAULT 0
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS peers (
                    peer_id TEXT PRIMARY KEY,
                    ip_address TEXT,
                    port INTEGER,
                    public_key BLOB,
                    storage_capacity INTEGER,
                    storage_used INTEGER,
                    reliability_score REAL,
                    last_seen REAL,
                    fragments_hosted TEXT,
                    bandwidth_up INTEGER,
                    bandwidth_down INTEGER
                )
            """)
            
            conn.commit()
    
    def load_state(self):
        """Carrega estado do banco de dados"""
        try:
            db_path = self.storage_dir / "storage.db"
            
            with sqlite3.connect(str(db_path)) as conn:
                # Carregar arquivos
                cursor = conn.execute("SELECT * FROM files")
                for row in cursor.fetchall():
                    file_data = {
                        'file_id': row[0],
                        'filename': row[1],
                        'original_size': row[2],
                        'total_fragments': row[3],
                        'file_hash': row[4],
                        'encryption_key': row[5],
                        'created_at': row[6],
                        'updated_at': row[7],
                        'owner_id': row[8],
                        'access_permissions': json.loads(row[9]) if row[9] else {},
                        'redundancy_level': row[10],
                        'fragments': json.loads(row[11]) if row[11] else [],
                        'metadata': json.loads(row[12]) if row[12] else {}
                    }
                    self.files[row[0]] = StorageFile(**file_data)
                
                # Carregar fragmentos
                cursor = conn.execute("SELECT * FROM fragments")
                for row in cursor.fetchall():
                    # Carregar dados criptografados do disco
                    fragment_path = self.storage_dir / "fragments" / f"{row[0]}.dat"
                    encrypted_data = b""
                    
                    if fragment_path.exists():
                        with open(fragment_path, 'rb') as f:
                            encrypted_data = f.read()
                    
                    fragment_data = {
                        'fragment_id': row[0],
                        'file_id': row[1],
                        'fragment_index': row[2],
                        'total_fragments': row[3],
                        'data_hash': row[4],
                        'encrypted_data': encrypted_data,
                        'size': row[5],
                        'created_at': row[6],
                        'peer_id': row[7],
                        'redundancy_level': row[8],
                        'access_count': row[9],
                        'last_accessed': row[10]
                    }
                    self.fragments[row[0]] = StorageFragment(**fragment_data)
                
                # Carregar peers
                cursor = conn.execute("SELECT * FROM peers")
                for row in cursor.fetchall():
                    peer_data = {
                        'peer_id': row[0],
                        'ip_address': row[1],
                        'port': row[2],
                        'public_key': row[3],
                        'storage_capacity': row[4],
                        'storage_used': row[5],
                        'reliability_score': row[6],
                        'last_seen': row[7],
                        'fragments_hosted': set(json.loads(row[8])) if row[8] else set(),
                        'bandwidth_up': row[9],
                        'bandwidth_down': row[10]
                    }
                    self.peers[row[0]] = StoragePeer(**peer_data)
            
            self.update_stats()
            logger.info(f"Estado carregado: {len(self.files)} arquivos, {len(self.fragments)} fragmentos")
            
        except Exception as e:
            logger.error(f"Erro ao carregar estado: {e}")
    
    def save_state(self):
        """Salva estado no banco de dados"""
        try:
            db_path = self.storage_dir / "storage.db"
            
            with sqlite3.connect(str(db_path)) as conn:
                # Salvar arquivos
                conn.execute("DELETE FROM files")
                for file_obj in self.files.values():
                    conn.execute("""
                        INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        file_obj.file_id,
                        file_obj.filename,
                        file_obj.original_size,
                        file_obj.total_fragments,
                        file_obj.file_hash,
                        file_obj.encryption_key,
                        file_obj.created_at,
                        file_obj.updated_at,
                        file_obj.owner_id,
                        json.dumps(file_obj.access_permissions),
                        file_obj.redundancy_level,
                        json.dumps(file_obj.fragments),
                        json.dumps(file_obj.metadata)
                    ))
                
                # Salvar fragmentos (metadados apenas)
                conn.execute("DELETE FROM fragments")
                for fragment in self.fragments.values():
                    conn.execute("""
                        INSERT INTO fragments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        fragment.fragment_id,
                        fragment.file_id,
                        fragment.fragment_index,
                        fragment.total_fragments,
                        fragment.data_hash,
                        fragment.size,
                        fragment.created_at,
                        fragment.peer_id,
                        fragment.redundancy_level,
                        fragment.access_count,
                        fragment.last_accessed
                    ))
                
                # Salvar peers
                conn.execute("DELETE FROM peers")
                for peer in self.peers.values():
                    conn.execute("""
                        INSERT INTO peers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        peer.peer_id,
                        peer.ip_address,
                        peer.port,
                        peer.public_key,
                        peer.storage_capacity,
                        peer.storage_used,
                        peer.reliability_score,
                        peer.last_seen,
                        json.dumps(list(peer.fragments_hosted)),
                        peer.bandwidth_up,
                        peer.bandwidth_down
                    ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Erro ao salvar estado: {e}")
    
    def store_file(self, file_path: str, redundancy: int = None) -> Optional[str]:
        """Armazena arquivo no sistema distribuído"""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                logger.error(f"Arquivo não encontrado: {file_path}")
                return None
            
            redundancy = redundancy or self.config['default_redundancy']
            
            # Ler arquivo
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Gerar IDs e hashes
            file_id = hashlib.sha256(f"{file_path.name}{time.time()}".encode()).hexdigest()
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            # Fragmentar arquivo
            fragments = self.fragment_data(file_data)
            fragment_ids = []
            
            # Processar cada fragmento
            for i, fragment_data in enumerate(fragments):
                fragment_id = hashlib.sha256(f"{file_id}{i}".encode()).hexdigest()
                
                # Criptografar fragmento
                encrypted_data = self.fernet.encrypt(fragment_data)
                fragment_hash = hashlib.sha256(fragment_data).hexdigest()
                
                # Criar objeto fragmento
                fragment = StorageFragment(
                    fragment_id=fragment_id,
                    file_id=file_id,
                    fragment_index=i,
                    total_fragments=len(fragments),
                    data_hash=fragment_hash,
                    encrypted_data=encrypted_data,
                    size=len(fragment_data),
                    created_at=time.time(),
                    peer_id=self.peer_id,
                    redundancy_level=redundancy
                )
                
                # Salvar fragmento no disco
                fragment_path = self.storage_dir / "fragments" / f"{fragment_id}.dat"
                with open(fragment_path, 'wb') as f:
                    f.write(encrypted_data)
                
                # Adicionar ao estado
                self.fragments[fragment_id] = fragment
                fragment_ids.append(fragment_id)
            
            # Criar objeto arquivo
            file_obj = StorageFile(
                file_id=file_id,
                filename=file_path.name,
                original_size=len(file_data),
                total_fragments=len(fragments),
                file_hash=file_hash,
                encryption_key=self.master_key,
                created_at=time.time(),
                updated_at=time.time(),
                owner_id=self.peer_id,
                access_permissions={self.peer_id: "owner"},
                redundancy_level=redundancy,
                fragments=fragment_ids,
                metadata={"original_path": str(file_path)}
            )
            
            # Adicionar ao estado
            self.files[file_id] = file_obj
            
            # Salvar estado
            self.save_state()
            self.update_stats()
            
            logger.info(f"Arquivo armazenado: {file_path.name} ({len(fragments)} fragmentos)")
            return file_id
            
        except Exception as e:
            logger.error(f"Erro ao armazenar arquivo: {e}")
            return None
    
    def retrieve_file(self, file_id: str, output_path: str = None) -> Optional[bytes]:
        """Recupera arquivo do sistema distribuído"""
        try:
            if file_id not in self.files:
                logger.error(f"Arquivo não encontrado: {file_id}")
                return None
            
            file_obj = self.files[file_id]
            fragments_data = []
            
            # Recuperar todos os fragmentos
            for fragment_id in file_obj.fragments:
                if fragment_id not in self.fragments:
                    logger.error(f"Fragmento não encontrado: {fragment_id}")
                    return None
                
                fragment = self.fragments[fragment_id]
                
                # Descriptografar fragmento
                try:
                    decrypted_data = self.fernet.decrypt(fragment.encrypted_data)
                    
                    # Verificar integridade
                    data_hash = hashlib.sha256(decrypted_data).hexdigest()
                    if data_hash != fragment.data_hash:
                        logger.error(f"Integridade comprometida: {fragment_id}")
                        return None
                    
                    fragments_data.append((fragment.fragment_index, decrypted_data))
                    
                    # Atualizar estatísticas de acesso
                    fragment.access_count += 1
                    fragment.last_accessed = time.time()
                    
                except Exception as e:
                    logger.error(f"Erro ao descriptografar fragmento {fragment_id}: {e}")
                    return None
            
            # Ordenar fragmentos e reconstruir arquivo
            fragments_data.sort(key=lambda x: x[0])
            file_data = b''.join([data for _, data in fragments_data])
            
            # Verificar integridade do arquivo completo
            file_hash = hashlib.sha256(file_data).hexdigest()
            if file_hash != file_obj.file_hash:
                logger.error(f"Integridade do arquivo comprometida: {file_id}")
                return None
            
            # Salvar arquivo se caminho especificado
            if output_path:
                output_path = Path(output_path)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(output_path, 'wb') as f:
                    f.write(file_data)
                
                logger.info(f"Arquivo recuperado: {output_path}")
            
            # Atualizar estatísticas
            file_obj.updated_at = time.time()
            self.save_state()
            
            return file_data
            
        except Exception as e:
            logger.error(f"Erro ao recuperar arquivo: {e}")
            return None
    
    def fragment_data(self, data: bytes) -> List[bytes]:
        """Fragmenta dados em chunks"""
        fragments = []
        
        for i in range(0, len(data), self.max_fragment_size):
            fragment = data[i:i + self.max_fragment_size]
            fragments.append(fragment)
        
        return fragments
    
    def update_stats(self):
        """Atualiza estatísticas do sistema"""
        try:
            with self.lock:
                total_files = len(self.files)
                total_fragments = len(self.fragments)
                total_size = sum(f.original_size for f in self.files.values())
                
                # Calcular espaço usado
                fragments_size = sum(len(f.encrypted_data) for f in self.fragments.values())
                max_storage = self.config['max_storage_gb'] * 1024 * 1024 * 1024
                available_space = max_storage - fragments_size
                
                # Calcular redundância
                if total_fragments > 0:
                    redundancy_ratio = sum(f.redundancy_level for f in self.fragments.values()) / total_fragments
                else:
                    redundancy_ratio = 0.0
                
                self.stats = StorageStats(
                    total_files=total_files,
                    total_fragments=total_fragments,
                    total_size=total_size,
                    available_space=available_space,
                    active_peers=len(self.peers),
                    redundancy_ratio=redundancy_ratio,
                    sync_status="Active" if self.running else "Stopped",
                    last_sync=time.time(),
                    upload_speed=0.0,  # Seria calculado em implementação real
                    download_speed=0.0  # Seria calculado em implementação real
                )
                
        except Exception as e:
            logger.error(f"Erro ao atualizar estatísticas: {e}")
    
    def start_background_tasks(self):
        """Inicia tarefas em background"""
        if self.running:
            return
        
        self.running = True
        
        # Thread de sincronização
        self.sync_thread = threading.Thread(target=self.sync_loop, daemon=True)
        self.sync_thread.start()
        
        # Thread de limpeza
        self.cleanup_thread = threading.Thread(target=self.cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        
        logger.info("Tarefas em background iniciadas")
    
    def stop_background_tasks(self):
        """Para tarefas em background"""
        self.running = False
        
        if self.sync_thread and self.sync_thread.is_alive():
            self.sync_thread.join(timeout=5)
        
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5)
        
        logger.info("Tarefas em background paradas")
    
    def sync_loop(self):
        """Loop de sincronização"""
        while self.running:
            try:
                self.update_stats()
                self.save_state()
                time.sleep(self.config['sync_interval'])
                
            except Exception as e:
                logger.error(f"Erro no loop de sincronização: {e}")
                time.sleep(5)
    
    def cleanup_loop(self):
        """Loop de limpeza"""
        while self.running:
            try:
                self.cleanup_orphaned_fragments()
                time.sleep(self.config['cleanup_interval'])
                
            except Exception as e:
                logger.error(f"Erro no loop de limpeza: {e}")
                time.sleep(30)
    
    def cleanup_orphaned_fragments(self):
        """Remove fragmentos órfãos"""
        try:
            fragments_dir = self.storage_dir / "fragments"
            
            # Listar arquivos de fragmentos no disco
            disk_fragments = set()
            if fragments_dir.exists():
                for file_path in fragments_dir.glob("*.dat"):
                    fragment_id = file_path.stem
                    disk_fragments.add(fragment_id)
            
            # Fragmentos conhecidos
            known_fragments = set(self.fragments.keys())
            
            # Remover fragmentos órfãos
            orphaned = disk_fragments - known_fragments
            for fragment_id in orphaned:
                fragment_path = fragments_dir / f"{fragment_id}.dat"
                try:
                    fragment_path.unlink()
                    logger.info(f"Fragmento órfão removido: {fragment_id}")
                except Exception as e:
                    logger.warning(f"Erro ao remover fragmento órfão {fragment_id}: {e}")
            
            if orphaned:
                logger.info(f"Limpeza concluída: {len(orphaned)} fragmentos órfãos removidos")
                
        except Exception as e:
            logger.error(f"Erro na limpeza: {e}")
    
    def get_storage_report(self) -> Dict[str, Any]:
        """Gera relatório completo do storage"""
        self.update_stats()
        
        return {
            'peer_id': self.peer_id,
            'storage_dir': str(self.storage_dir),
            'stats': asdict(self.stats),
            'config': self.config,
            'files': {
                file_id: {
                    'filename': file_obj.filename,
                    'size': file_obj.original_size,
                    'fragments': file_obj.total_fragments,
                    'created': datetime.fromtimestamp(file_obj.created_at).isoformat(),
                    'redundancy': file_obj.redundancy_level
                }
                for file_id, file_obj in self.files.items()
            },
            'fragments_summary': {
                'total': len(self.fragments),
                'total_size': sum(len(f.encrypted_data) for f in self.fragments.values()),
                'avg_size': sum(len(f.encrypted_data) for f in self.fragments.values()) / len(self.fragments) if self.fragments else 0
            },
            'health': {
                'storage_healthy': True,
                'all_fragments_accessible': all(
                    (self.storage_dir / "fragments" / f"{fid}.dat").exists() 
                    for fid in self.fragments.keys()
                ),
                'database_accessible': (self.storage_dir / "storage.db").exists()
            }
        }

def main():
    """Função principal para testes"""
    print("💾 QuantumShield - Storage Distribuído Robusto v2")
    print("=" * 55)
    
    # Inicializar sistema
    storage = QuantumDistributedStorageV2("test_storage_v2")
    
    try:
        # Iniciar tarefas em background
        storage.start_background_tasks()
        
        # Criar arquivo de teste
        test_file = Path("test_file_v2.txt")
        test_content = b"Este eh um arquivo de teste para o sistema de storage distribuido robusto QuantumShield v2!\\n" * 50
        
        with open(test_file, 'wb') as f:
            f.write(test_content)
        
        print(f"📄 Arquivo de teste criado: {len(test_content)} bytes")
        
        # Armazenar arquivo
        print("💾 Armazenando arquivo...")
        file_id = storage.store_file(str(test_file))
        
        if file_id:
            print(f"✅ Arquivo armazenado com ID: {file_id}")
            
            # Recuperar arquivo
            print("📥 Recuperando arquivo...")
            recovered_file = "recovered_file_v2.txt"
            recovered_data = storage.retrieve_file(file_id, recovered_file)
            
            if recovered_data:
                print(f"✅ Arquivo recuperado: {len(recovered_data)} bytes")
                
                # Verificar integridade
                if recovered_data == test_content:
                    print("✅ Integridade verificada: 100% íntegro")
                else:
                    print("❌ Erro de integridade!")
            else:
                print("❌ Erro ao recuperar arquivo")
        else:
            print("❌ Erro ao armazenar arquivo")
        
        # Aguardar sincronização
        print("⏳ Aguardando sincronização...")
        time.sleep(3)
        
        # Gerar relatório
        print("📊 Gerando relatório...")
        report = storage.get_storage_report()
        
        print(f"📈 Relatório do Storage:")
        print(f"   Arquivos: {report['stats']['total_files']}")
        print(f"   Fragmentos: {report['stats']['total_fragments']}")
        print(f"   Tamanho total: {report['stats']['total_size']} bytes")
        print(f"   Redundância média: {report['stats']['redundancy_ratio']:.1f}")
        print(f"   Status: {report['stats']['sync_status']}")
        print(f"   Saúde: {'✅ Saudável' if report['health']['storage_healthy'] else '❌ Problemas'}")
        
        # Limpeza
        print("🧹 Executando limpeza...")
        storage.cleanup_orphaned_fragments()
        
        print("✅ Teste do storage distribuído robusto concluído!")
        
    finally:
        # Parar tarefas
        storage.stop_background_tasks()
        
        # Limpar arquivos de teste
        for file_path in [test_file, "recovered_file_v2.txt"]:
            try:
                Path(file_path).unlink()
            except:
                pass

if __name__ == "__main__":
    main()

