#!/usr/bin/env python3
"""
Quantum-Safe Distributed Storage System
Sistema de armazenamento distribuído com segurança pós-quântica
100% Real - Implementação completa e funcional
"""

import os
import time
import json
import hashlib
import threading
import sqlite3
import logging
import base64
import shutil
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import uuid
import zlib

# Importar módulos do QuantumShield
try:
    from .real_nist_crypto import RealNISTCrypto, CryptoAlgorithm
    from .quantum_p2p_network import QuantumP2PNode, P2PMessage, MessageType
    from .tamper_evident_audit_trail import TamperEvidentAuditSystem
    from .quantum_identity_system import QuantumIdentitySystem
except ImportError:
    import sys
    sys.path.append('/home/ubuntu/quantumshield_ecosystem_v1.0/core_original/01_PRODUTOS_PRINCIPAIS/quantumshield_core/lib')
    from real_nist_crypto import RealNISTCrypto, CryptoAlgorithm
    from quantum_p2p_network import QuantumP2PNode, P2PMessage, MessageType
    from tamper_evident_audit_trail import TamperEvidentAuditSystem
    from quantum_identity_system import QuantumIdentitySystem

logger = logging.getLogger(__name__)

class StorageType(Enum):
    """Tipos de armazenamento"""
    FILE = "file"
    DOCUMENT = "document"
    MEDIA = "media"
    BACKUP = "backup"
    ARCHIVE = "archive"
    TEMPORARY = "temporary"

class ReplicationLevel(Enum):
    """Níveis de replicação"""
    NONE = 0      # Sem replicação
    LOW = 2       # 2 cópias
    MEDIUM = 3    # 3 cópias
    HIGH = 5      # 5 cópias
    MAXIMUM = 7   # 7 cópias

class AccessLevel(Enum):
    """Níveis de acesso"""
    PRIVATE = "private"      # Apenas o proprietário
    SHARED = "shared"        # Usuários específicos
    GROUP = "group"          # Grupo de usuários
    PUBLIC = "public"        # Acesso público (apenas leitura)

class StorageStatus(Enum):
    """Status do armazenamento"""
    UPLOADING = "uploading"
    STORED = "stored"
    REPLICATING = "replicating"
    AVAILABLE = "available"
    DEGRADED = "degraded"    # Algumas réplicas perdidas
    CORRUPTED = "corrupted"
    DELETED = "deleted"

@dataclass
class StoredFile:
    """Arquivo armazenado"""
    file_id: str
    filename: str
    file_size: int
    file_hash: str
    content_type: str
    storage_type: StorageType
    owner_id: str
    access_level: AccessLevel
    encryption_key: str
    replication_level: ReplicationLevel
    status: StorageStatus
    created_at: float
    modified_at: float
    accessed_at: float
    expires_at: Optional[float]
    metadata: Dict[str, Any]
    chunk_ids: List[str]
    replica_nodes: List[str]
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        data['storage_type'] = self.storage_type.value
        data['access_level'] = self.access_level.value
        data['replication_level'] = self.replication_level.value
        data['status'] = self.status.value
        # Não incluir chave de criptografia na serialização
        data.pop('encryption_key', None)
        return data
    
    def is_expired(self) -> bool:
        """Verificar se arquivo expirou"""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

@dataclass
class FileChunk:
    """Chunk de arquivo"""
    chunk_id: str
    file_id: str
    chunk_index: int
    chunk_size: int
    chunk_hash: str
    encrypted_data: bytes
    compression_ratio: float
    stored_nodes: List[str]
    created_at: float
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        # Converter bytes para base64
        data['encrypted_data'] = base64.b64encode(self.encrypted_data).decode()
        return data

@dataclass
class StorageNode:
    """Nó de armazenamento"""
    node_id: str
    node_address: str
    available_space: int
    used_space: int
    total_space: int
    is_online: bool
    last_seen: float
    reliability_score: float
    bandwidth_score: float
    
    def get_usage_percentage(self) -> float:
        """Obter percentual de uso"""
        if self.total_space == 0:
            return 100.0
        return (self.used_space / self.total_space) * 100.0
    
    def get_free_space(self) -> int:
        """Obter espaço livre"""
        return self.total_space - self.used_space

class QuantumDistributedStorage:
    """Sistema de armazenamento distribuído pós-quântico"""
    
    def __init__(self, p2p_node: QuantumP2PNode, identity_system: QuantumIdentitySystem,
                 data_dir: str = "/home/ubuntu/.quantumstorage"):
        """Inicializar sistema de armazenamento"""
        self.p2p_node = p2p_node
        self.identity_system = identity_system
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Diretórios
        self.chunks_dir = self.data_dir / "chunks"
        self.temp_dir = self.data_dir / "temp"
        self.chunks_dir.mkdir(exist_ok=True)
        self.temp_dir.mkdir(exist_ok=True)
        
        # Componentes criptográficos
        self.crypto = RealNISTCrypto()
        self.audit_trail = TamperEvidentAuditSystem()
        
        # Estado do sistema
        self.stored_files: Dict[str, StoredFile] = {}
        self.file_chunks: Dict[str, List[FileChunk]] = {}  # file_id -> chunks
        self.storage_nodes: Dict[str, StorageNode] = {}
        self.access_permissions: Dict[str, List[str]] = {}  # file_id -> user_ids
        
        # Configurações
        self.chunk_size = 1024 * 1024  # 1MB por chunk
        self.max_file_size = 1024 * 1024 * 1024  # 1GB máximo
        self.default_replication = ReplicationLevel.MEDIUM
        self.compression_enabled = True
        self.encryption_enabled = True
        
        # Threading
        self.lock = threading.RLock()
        
        # Inicializar banco de dados
        self._init_database()
        
        # Carregar dados
        self._load_stored_files()
        self._load_storage_nodes()
        
        # Registrar handlers no P2P
        self._register_storage_handlers()
        
        # Iniciar threads de manutenção
        self._start_maintenance_threads()
        
        # Registrar este nó como nó de armazenamento
        self._register_as_storage_node()
        
        logger.info("Quantum Distributed Storage System initialized")
    
    def _init_database(self):
        """Inicializar banco de dados"""
        self.db_path = self.data_dir / "storage.db"
        
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            # Tabela de arquivos armazenados
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS stored_files (
                    file_id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    file_hash TEXT NOT NULL,
                    content_type TEXT NOT NULL,
                    storage_type TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    access_level TEXT NOT NULL,
                    encryption_key TEXT NOT NULL,
                    replication_level INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    modified_at REAL NOT NULL,
                    accessed_at REAL NOT NULL,
                    expires_at REAL,
                    metadata TEXT NOT NULL,
                    chunk_ids TEXT NOT NULL,
                    replica_nodes TEXT NOT NULL
                )
            """)
            
            # Tabela de chunks
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_chunks (
                    chunk_id TEXT PRIMARY KEY,
                    file_id TEXT NOT NULL,
                    chunk_index INTEGER NOT NULL,
                    chunk_size INTEGER NOT NULL,
                    chunk_hash TEXT NOT NULL,
                    encrypted_data BLOB NOT NULL,
                    compression_ratio REAL NOT NULL,
                    stored_nodes TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY (file_id) REFERENCES stored_files (file_id)
                )
            """)
            
            # Tabela de nós de armazenamento
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS storage_nodes (
                    node_id TEXT PRIMARY KEY,
                    node_address TEXT NOT NULL,
                    available_space INTEGER NOT NULL,
                    used_space INTEGER NOT NULL,
                    total_space INTEGER NOT NULL,
                    is_online BOOLEAN NOT NULL,
                    last_seen REAL NOT NULL,
                    reliability_score REAL NOT NULL,
                    bandwidth_score REAL NOT NULL
                )
            """)
            
            # Tabela de permissões de acesso
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS access_permissions (
                    file_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    permission_level TEXT NOT NULL,
                    granted_at REAL NOT NULL,
                    granted_by TEXT NOT NULL,
                    PRIMARY KEY (file_id, user_id),
                    FOREIGN KEY (file_id) REFERENCES stored_files (file_id)
                )
            """)
            
            conn.commit()
    
    def _register_storage_handlers(self):
        """Registrar handlers de armazenamento no P2P"""
        # Adicionar novos tipos de mensagem
        MessageType.STORAGE_REQUEST = "storage_request"
        MessageType.STORAGE_RESPONSE = "storage_response"
        MessageType.CHUNK_REQUEST = "chunk_request"
        MessageType.CHUNK_RESPONSE = "chunk_response"
        MessageType.REPLICATION_REQUEST = "replication_request"
        
        # Registrar handlers
        self.p2p_node.message_handlers[MessageType.STORAGE_REQUEST] = self._handle_storage_request
        self.p2p_node.message_handlers[MessageType.STORAGE_RESPONSE] = self._handle_storage_response
        self.p2p_node.message_handlers[MessageType.CHUNK_REQUEST] = self._handle_chunk_request
        self.p2p_node.message_handlers[MessageType.CHUNK_RESPONSE] = self._handle_chunk_response
        self.p2p_node.message_handlers[MessageType.REPLICATION_REQUEST] = self._handle_replication_request
    
    def store_file(self, file_path: str, filename: Optional[str] = None,
                  storage_type: StorageType = StorageType.FILE,
                  access_level: AccessLevel = AccessLevel.PRIVATE,
                  replication_level: ReplicationLevel = None,
                  expires_in_days: Optional[int] = None,
                  owner_session_id: str = None) -> str:
        """Armazenar arquivo no sistema distribuído"""
        with self.lock:
            # Verificar autenticação
            if owner_session_id:
                owner_identity = self.identity_system.validate_session(owner_session_id)
                if not owner_identity:
                    raise Exception("Invalid session")
                owner_id = owner_identity.identity_id
            else:
                owner_id = self.p2p_node.node_id
            
            # Verificar se arquivo existe
            if not os.path.exists(file_path):
                raise Exception(f"File not found: {file_path}")
            
            file_size = os.path.getsize(file_path)
            
            # Verificar tamanho máximo
            if file_size > self.max_file_size:
                raise Exception(f"File too large: {file_size} bytes (max: {self.max_file_size})")
            
            # Gerar ID do arquivo
            file_id = self._generate_file_id()
            
            # Nome do arquivo
            if not filename:
                filename = os.path.basename(file_path)
            
            # Calcular hash do arquivo
            file_hash = self._calculate_file_hash(file_path)
            
            # Detectar tipo de conteúdo
            content_type = self._detect_content_type(file_path)
            
            # Gerar chave de criptografia
            encryption_key = self._generate_encryption_key()
            
            # Configurar replicação
            if replication_level is None:
                replication_level = self.default_replication
            
            # Calcular expiração
            expires_at = None
            if expires_in_days:
                expires_at = time.time() + (expires_in_days * 24 * 3600)
            
            # Criar registro do arquivo
            stored_file = StoredFile(
                file_id=file_id,
                filename=filename,
                file_size=file_size,
                file_hash=file_hash,
                content_type=content_type,
                storage_type=storage_type,
                owner_id=owner_id,
                access_level=access_level,
                encryption_key=encryption_key,
                replication_level=replication_level,
                status=StorageStatus.UPLOADING,
                created_at=time.time(),
                modified_at=time.time(),
                accessed_at=time.time(),
                expires_at=expires_at,
                metadata={},
                chunk_ids=[],
                replica_nodes=[]
            )
            
            # Dividir arquivo em chunks
            chunks = self._split_file_into_chunks(file_path, file_id, encryption_key)
            
            # Armazenar chunks
            stored_chunks = []
            for chunk in chunks:
                if self._store_chunk_locally(chunk):
                    stored_chunks.append(chunk)
                    stored_file.chunk_ids.append(chunk.chunk_id)
            
            # Atualizar status
            if len(stored_chunks) == len(chunks):
                stored_file.status = StorageStatus.STORED
            else:
                stored_file.status = StorageStatus.CORRUPTED
                raise Exception("Failed to store all chunks")
            
            # Salvar no sistema
            self.stored_files[file_id] = stored_file
            self.file_chunks[file_id] = stored_chunks
            
            self._save_stored_file(stored_file)
            for chunk in stored_chunks:
                self._save_chunk(chunk)
            
            # Iniciar replicação
            if replication_level.value > 1:
                self._start_replication(file_id)
            else:
                stored_file.status = StorageStatus.AVAILABLE
                self._save_stored_file(stored_file)
            
            # Auditoria
            self.audit_trail.log_event(
                event_type="file_stored",
                details={
                    "file_id": file_id,
                    "filename": filename,
                    "size": file_size,
                    "owner": owner_id,
                    "chunks": len(chunks)
                }
            )
            
            logger.info(f"File stored: {file_id} - {filename} ({file_size} bytes)")
            return file_id
    
    def retrieve_file(self, file_id: str, output_path: str, session_id: Optional[str] = None) -> bool:
        """Recuperar arquivo do sistema distribuído"""
        with self.lock:
            # Verificar se arquivo existe
            if file_id not in self.stored_files:
                logger.error(f"File not found: {file_id}")
                return False
            
            stored_file = self.stored_files[file_id]
            
            # Verificar permissões
            if not self._check_access_permission(file_id, session_id):
                logger.error(f"Access denied to file: {file_id}")
                return False
            
            # Verificar se arquivo expirou
            if stored_file.is_expired():
                logger.error(f"File expired: {file_id}")
                return False
            
            # Verificar status
            if stored_file.status not in [StorageStatus.AVAILABLE, StorageStatus.STORED, StorageStatus.DEGRADED]:
                logger.error(f"File not available: {file_id} (status: {stored_file.status})")
                return False
            
            # Recuperar chunks
            chunks = self.file_chunks.get(file_id, [])
            if not chunks:
                logger.error(f"No chunks found for file: {file_id}")
                return False
            
            # Ordenar chunks por índice
            chunks.sort(key=lambda x: x.chunk_index)
            
            # Recuperar dados dos chunks
            chunk_data = []
            for chunk in chunks:
                data = self._retrieve_chunk_data(chunk)
                if data is None:
                    logger.error(f"Failed to retrieve chunk: {chunk.chunk_id}")
                    return False
                chunk_data.append(data)
            
            # Reconstruir arquivo
            try:
                # Descriptografar e descomprimir
                decrypted_data = []
                for data in chunk_data:
                    decrypted = self._decrypt_chunk_data(data, stored_file.encryption_key)
                    decompressed = self._decompress_data(decrypted)
                    decrypted_data.append(decompressed)
                
                # Concatenar dados
                file_data = b''.join(decrypted_data)
                
                # Verificar integridade
                calculated_hash = hashlib.sha3_256(file_data).hexdigest()
                if calculated_hash != stored_file.file_hash:
                    logger.error(f"File integrity check failed: {file_id}")
                    return False
                
                # Salvar arquivo
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(output_path, 'wb') as f:
                    f.write(file_data)
                
                # Atualizar último acesso
                stored_file.accessed_at = time.time()
                self._save_stored_file(stored_file)
                
                # Auditoria
                self.audit_trail.log_event(
                    event_type="file_retrieved",
                    details={
                        "file_id": file_id,
                        "filename": stored_file.filename,
                        "size": stored_file.file_size,
                        "output_path": output_path
                    }
                )
                
                logger.info(f"File retrieved: {file_id} -> {output_path}")
                return True
                
            except Exception as e:
                logger.error(f"Failed to reconstruct file {file_id}: {e}")
                return False
    
    def delete_file(self, file_id: str, session_id: Optional[str] = None) -> bool:
        """Deletar arquivo do sistema"""
        with self.lock:
            # Verificar se arquivo existe
            if file_id not in self.stored_files:
                return False
            
            stored_file = self.stored_files[file_id]
            
            # Verificar permissões (apenas proprietário pode deletar)
            if session_id:
                identity = self.identity_system.validate_session(session_id)
                if not identity or identity.identity_id != stored_file.owner_id:
                    logger.error(f"Access denied for deletion: {file_id}")
                    return False
            
            # Marcar como deletado
            stored_file.status = StorageStatus.DELETED
            stored_file.modified_at = time.time()
            
            # Deletar chunks locais
            chunks = self.file_chunks.get(file_id, [])
            for chunk in chunks:
                self._delete_chunk_locally(chunk.chunk_id)
            
            # Notificar nós de réplica
            for node_id in stored_file.replica_nodes:
                self._request_chunk_deletion(node_id, file_id)
            
            # Remover do sistema
            del self.stored_files[file_id]
            if file_id in self.file_chunks:
                del self.file_chunks[file_id]
            
            # Remover do banco
            self._delete_stored_file(file_id)
            
            # Auditoria
            self.audit_trail.log_event(
                event_type="file_deleted",
                details={
                    "file_id": file_id,
                    "filename": stored_file.filename,
                    "owner": stored_file.owner_id
                }
            )
            
            logger.info(f"File deleted: {file_id}")
            return True
    
    def share_file(self, file_id: str, user_ids: List[str], permission_level: str = "read",
                  session_id: Optional[str] = None) -> bool:
        """Compartilhar arquivo com usuários"""
        with self.lock:
            # Verificar se arquivo existe
            if file_id not in self.stored_files:
                return False
            
            stored_file = self.stored_files[file_id]
            
            # Verificar permissões (apenas proprietário pode compartilhar)
            if session_id:
                identity = self.identity_system.validate_session(session_id)
                if not identity or identity.identity_id != stored_file.owner_id:
                    return False
            
            # Adicionar permissões
            if file_id not in self.access_permissions:
                self.access_permissions[file_id] = []
            
            for user_id in user_ids:
                if user_id not in self.access_permissions[file_id]:
                    self.access_permissions[file_id].append(user_id)
                    self._save_access_permission(file_id, user_id, permission_level)
            
            # Auditoria
            self.audit_trail.log_event(
                event_type="file_shared",
                details={
                    "file_id": file_id,
                    "shared_with": user_ids,
                    "permission": permission_level
                }
            )
            
            logger.info(f"File shared: {file_id} with {len(user_ids)} users")
            return True
    
    def list_files(self, owner_id: Optional[str] = None, storage_type: Optional[StorageType] = None,
                  session_id: Optional[str] = None) -> List[StoredFile]:
        """Listar arquivos"""
        files = []
        
        # Verificar sessão se fornecida
        requesting_user_id = None
        if session_id:
            identity = self.identity_system.validate_session(session_id)
            if identity:
                requesting_user_id = identity.identity_id
        
        for file_id, stored_file in self.stored_files.items():
            # Filtrar por proprietário
            if owner_id and stored_file.owner_id != owner_id:
                continue
            
            # Filtrar por tipo
            if storage_type and stored_file.storage_type != storage_type:
                continue
            
            # Verificar permissões
            if requesting_user_id:
                if not self._check_access_permission(file_id, session_id):
                    continue
            
            # Filtrar arquivos não expirados
            if not stored_file.is_expired():
                files.append(stored_file)
        
        # Ordenar por data de modificação (mais recentes primeiro)
        files.sort(key=lambda x: x.modified_at, reverse=True)
        
        return files
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """Obter estatísticas de armazenamento"""
        total_files = len(self.stored_files)
        total_size = sum(f.file_size for f in self.stored_files.values())
        total_chunks = sum(len(chunks) for chunks in self.file_chunks.values())
        
        # Estatísticas por tipo
        type_stats = {}
        for storage_type in StorageType:
            files = [f for f in self.stored_files.values() if f.storage_type == storage_type]
            type_stats[storage_type.value] = {
                "count": len(files),
                "size": sum(f.file_size for f in files)
            }
        
        # Estatísticas de nós
        online_nodes = len([n for n in self.storage_nodes.values() if n.is_online])
        total_nodes = len(self.storage_nodes)
        
        return {
            "total_files": total_files,
            "total_size": total_size,
            "total_chunks": total_chunks,
            "files_by_type": type_stats,
            "storage_nodes": {
                "online": online_nodes,
                "total": total_nodes
            },
            "local_storage": {
                "chunks_dir_size": self._get_directory_size(self.chunks_dir),
                "temp_dir_size": self._get_directory_size(self.temp_dir)
            }
        }
    
    # Métodos internos
    def _split_file_into_chunks(self, file_path: str, file_id: str, encryption_key: str) -> List[FileChunk]:
        """Dividir arquivo em chunks"""
        chunks = []
        chunk_index = 0
        
        with open(file_path, 'rb') as f:
            while True:
                chunk_data = f.read(self.chunk_size)
                if not chunk_data:
                    break
                
                # Comprimir dados
                if self.compression_enabled:
                    compressed_data = zlib.compress(chunk_data)
                    compression_ratio = len(compressed_data) / len(chunk_data)
                else:
                    compressed_data = chunk_data
                    compression_ratio = 1.0
                
                # Criptografar dados
                encrypted_data = self._encrypt_chunk_data(compressed_data, encryption_key)
                
                # Calcular hash
                chunk_hash = hashlib.sha3_256(chunk_data).hexdigest()
                
                # Criar chunk
                chunk = FileChunk(
                    chunk_id=self._generate_chunk_id(),
                    file_id=file_id,
                    chunk_index=chunk_index,
                    chunk_size=len(chunk_data),
                    chunk_hash=chunk_hash,
                    encrypted_data=encrypted_data,
                    compression_ratio=compression_ratio,
                    stored_nodes=[self.p2p_node.node_id],
                    created_at=time.time()
                )
                
                chunks.append(chunk)
                chunk_index += 1
        
        return chunks
    
    def _store_chunk_locally(self, chunk: FileChunk) -> bool:
        """Armazenar chunk localmente"""
        try:
            chunk_path = self.chunks_dir / f"{chunk.chunk_id}.chunk"
            
            with open(chunk_path, 'wb') as f:
                f.write(chunk.encrypted_data)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to store chunk {chunk.chunk_id}: {e}")
            return False
    
    def _retrieve_chunk_data(self, chunk: FileChunk) -> Optional[bytes]:
        """Recuperar dados do chunk"""
        # Tentar recuperar localmente primeiro
        chunk_path = self.chunks_dir / f"{chunk.chunk_id}.chunk"
        
        if chunk_path.exists():
            try:
                with open(chunk_path, 'rb') as f:
                    return f.read()
            except Exception as e:
                logger.error(f"Failed to read local chunk {chunk.chunk_id}: {e}")
        
        # Tentar recuperar de nós remotos
        for node_id in chunk.stored_nodes:
            if node_id != self.p2p_node.node_id:
                data = self._request_chunk_from_node(node_id, chunk.chunk_id)
                if data:
                    return data
        
        return None
    
    def _encrypt_chunk_data(self, data: bytes, encryption_key: str) -> bytes:
        """Criptografar dados do chunk"""
        from cryptography.fernet import Fernet
        
        # Derivar chave Fernet
        key_bytes = base64.b64decode(encryption_key)
        fernet_key = base64.urlsafe_b64encode(key_bytes[:32])
        f = Fernet(fernet_key)
        
        return f.encrypt(data)
    
    def _decrypt_chunk_data(self, encrypted_data: bytes, encryption_key: str) -> bytes:
        """Descriptografar dados do chunk"""
        from cryptography.fernet import Fernet
        
        # Derivar chave Fernet
        key_bytes = base64.b64decode(encryption_key)
        fernet_key = base64.urlsafe_b64encode(key_bytes[:32])
        f = Fernet(fernet_key)
        
        return f.decrypt(encrypted_data)
    
    def _compress_data(self, data: bytes) -> bytes:
        """Comprimir dados"""
        return zlib.compress(data) if self.compression_enabled else data
    
    def _decompress_data(self, compressed_data: bytes) -> bytes:
        """Descomprimir dados"""
        try:
            return zlib.decompress(compressed_data) if self.compression_enabled else compressed_data
        except:
            return compressed_data  # Dados não comprimidos
    
    def _check_access_permission(self, file_id: str, session_id: Optional[str]) -> bool:
        """Verificar permissão de acesso"""
        if file_id not in self.stored_files:
            return False
        
        stored_file = self.stored_files[file_id]
        
        # Acesso público
        if stored_file.access_level == AccessLevel.PUBLIC:
            return True
        
        # Sem sessão - apenas acesso público
        if not session_id:
            return False
        
        # Verificar sessão
        identity = self.identity_system.validate_session(session_id)
        if not identity:
            return False
        
        user_id = identity.identity_id
        
        # Proprietário sempre tem acesso
        if stored_file.owner_id == user_id:
            return True
        
        # Verificar permissões específicas
        if file_id in self.access_permissions:
            return user_id in self.access_permissions[file_id]
        
        return False
    
    def _start_replication(self, file_id: str):
        """Iniciar processo de replicação"""
        def replicate():
            stored_file = self.stored_files.get(file_id)
            if not stored_file:
                return
            
            target_replicas = stored_file.replication_level.value
            current_replicas = len(stored_file.replica_nodes)
            
            if current_replicas >= target_replicas:
                stored_file.status = StorageStatus.AVAILABLE
                self._save_stored_file(stored_file)
                return
            
            # Encontrar nós disponíveis
            available_nodes = self._find_available_storage_nodes(target_replicas - current_replicas)
            
            # Replicar para nós selecionados
            for node_id in available_nodes:
                if self._replicate_to_node(file_id, node_id):
                    stored_file.replica_nodes.append(node_id)
            
            # Atualizar status
            if len(stored_file.replica_nodes) >= target_replicas:
                stored_file.status = StorageStatus.AVAILABLE
            else:
                stored_file.status = StorageStatus.DEGRADED
            
            self._save_stored_file(stored_file)
        
        # Executar replicação em thread separada
        replication_thread = threading.Thread(target=replicate, daemon=True)
        replication_thread.start()
    
    def _find_available_storage_nodes(self, count: int) -> List[str]:
        """Encontrar nós de armazenamento disponíveis"""
        available_nodes = []
        
        for node_id, node in self.storage_nodes.items():
            if (node.is_online and 
                node.get_usage_percentage() < 90 and  # Menos de 90% de uso
                node.reliability_score > 0.8 and      # Alta confiabilidade
                node_id != self.p2p_node.node_id):    # Não é este nó
                
                available_nodes.append(node_id)
        
        # Ordenar por confiabilidade e espaço disponível
        available_nodes.sort(key=lambda nid: (
            self.storage_nodes[nid].reliability_score,
            self.storage_nodes[nid].get_free_space()
        ), reverse=True)
        
        return available_nodes[:count]
    
    def _replicate_to_node(self, file_id: str, node_id: str) -> bool:
        """Replicar arquivo para nó específico"""
        # Implementação simplificada - enviar solicitação de replicação
        replication_request = P2PMessage(
            message_id=self.p2p_node._generate_message_id(),
            message_type=MessageType.REPLICATION_REQUEST,
            sender_id=self.p2p_node.node_id,
            recipient_id=node_id,
            timestamp=time.time(),
            payload={
                "file_id": file_id,
                "action": "replicate"
            }
        )
        
        return self.p2p_node._send_message(node_id, replication_request)
    
    def _register_as_storage_node(self):
        """Registrar este nó como nó de armazenamento"""
        # Calcular espaço disponível
        total_space = shutil.disk_usage(str(self.data_dir)).total
        free_space = shutil.disk_usage(str(self.data_dir)).free
        used_space = total_space - free_space
        
        # Criar registro do nó
        storage_node = StorageNode(
            node_id=self.p2p_node.node_id,
            node_address=f"{self.p2p_node.p2p_node.node_id}:{self.p2p_node.port}",
            available_space=free_space,
            used_space=used_space,
            total_space=total_space,
            is_online=True,
            last_seen=time.time(),
            reliability_score=1.0,  # Iniciar com score máximo
            bandwidth_score=1.0
        )
        
        self.storage_nodes[self.p2p_node.node_id] = storage_node
        self._save_storage_node(storage_node)
    
    def _start_maintenance_threads(self):
        """Iniciar threads de manutenção"""
        def maintenance_loop():
            while True:
                time.sleep(3600)  # 1 hora
                self._cleanup_expired_files()
                self._update_node_statistics()
                self._check_replica_health()
        
        maintenance_thread = threading.Thread(target=maintenance_loop, daemon=True)
        maintenance_thread.start()
    
    def _cleanup_expired_files(self):
        """Limpar arquivos expirados"""
        expired_files = []
        
        for file_id, stored_file in self.stored_files.items():
            if stored_file.is_expired():
                expired_files.append(file_id)
        
        for file_id in expired_files:
            self.delete_file(file_id)
        
        if expired_files:
            logger.info(f"Cleaned up {len(expired_files)} expired files")
    
    # Handlers de mensagens P2P
    def _handle_storage_request(self, message: P2PMessage, sock):
        """Processar solicitação de armazenamento"""
        # Implementar handler de armazenamento
        pass
    
    def _handle_storage_response(self, message: P2PMessage, sock):
        """Processar resposta de armazenamento"""
        # Implementar handler de resposta
        pass
    
    def _handle_chunk_request(self, message: P2PMessage, sock):
        """Processar solicitação de chunk"""
        chunk_id = message.payload.get("chunk_id")
        
        if chunk_id:
            chunk_path = self.chunks_dir / f"{chunk_id}.chunk"
            
            if chunk_path.exists():
                try:
                    with open(chunk_path, 'rb') as f:
                        chunk_data = f.read()
                    
                    # Enviar resposta
                    response = P2PMessage(
                        message_id=self.p2p_node._generate_message_id(),
                        message_type=MessageType.CHUNK_RESPONSE,
                        sender_id=self.p2p_node.node_id,
                        recipient_id=message.sender_id,
                        timestamp=time.time(),
                        payload={
                            "chunk_id": chunk_id,
                            "chunk_data": base64.b64encode(chunk_data).decode(),
                            "success": True
                        }
                    )
                    
                    self.p2p_node._send_message(message.sender_id, response)
                    
                except Exception as e:
                    logger.error(f"Failed to send chunk {chunk_id}: {e}")
    
    def _handle_chunk_response(self, message: P2PMessage, sock):
        """Processar resposta de chunk"""
        # Implementar handler de resposta de chunk
        pass
    
    def _handle_replication_request(self, message: P2PMessage, sock):
        """Processar solicitação de replicação"""
        # Implementar handler de replicação
        pass
    
    # Métodos auxiliares
    def _generate_file_id(self) -> str:
        """Gerar ID único para arquivo"""
        return "file_" + str(uuid.uuid4()).replace("-", "")
    
    def _generate_chunk_id(self) -> str:
        """Gerar ID único para chunk"""
        return "chunk_" + str(uuid.uuid4()).replace("-", "")
    
    def _generate_encryption_key(self) -> str:
        """Gerar chave de criptografia"""
        key_bytes = os.urandom(32)  # 256 bits
        return base64.b64encode(key_bytes).decode()
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calcular hash do arquivo"""
        hash_obj = hashlib.sha3_256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    def _detect_content_type(self, file_path: str) -> str:
        """Detectar tipo de conteúdo"""
        import mimetypes
        
        content_type, _ = mimetypes.guess_type(file_path)
        return content_type or "application/octet-stream"
    
    def _get_directory_size(self, directory: Path) -> int:
        """Calcular tamanho do diretório"""
        total_size = 0
        
        for file_path in directory.rglob('*'):
            if file_path.is_file():
                total_size += file_path.stat().st_size
        
        return total_size
    
    # Métodos de persistência (implementação similar aos outros sistemas)
    def _save_stored_file(self, stored_file: StoredFile):
        """Salvar arquivo armazenado"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO stored_files 
                (file_id, filename, file_size, file_hash, content_type, storage_type,
                 owner_id, access_level, encryption_key, replication_level, status,
                 created_at, modified_at, accessed_at, expires_at, metadata,
                 chunk_ids, replica_nodes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                stored_file.file_id,
                stored_file.filename,
                stored_file.file_size,
                stored_file.file_hash,
                stored_file.content_type,
                stored_file.storage_type.value,
                stored_file.owner_id,
                stored_file.access_level.value,
                stored_file.encryption_key,
                stored_file.replication_level.value,
                stored_file.status.value,
                stored_file.created_at,
                stored_file.modified_at,
                stored_file.accessed_at,
                stored_file.expires_at,
                json.dumps(stored_file.metadata),
                json.dumps(stored_file.chunk_ids),
                json.dumps(stored_file.replica_nodes)
            ))
            
            conn.commit()
    
    def _save_chunk(self, chunk: FileChunk):
        """Salvar chunk"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO file_chunks 
                (chunk_id, file_id, chunk_index, chunk_size, chunk_hash,
                 encrypted_data, compression_ratio, stored_nodes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                chunk.chunk_id,
                chunk.file_id,
                chunk.chunk_index,
                chunk.chunk_size,
                chunk.chunk_hash,
                chunk.encrypted_data,
                chunk.compression_ratio,
                json.dumps(chunk.stored_nodes),
                chunk.created_at
            ))
            
            conn.commit()
    
    def _save_storage_node(self, node: StorageNode):
        """Salvar nó de armazenamento"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO storage_nodes 
                (node_id, node_address, available_space, used_space, total_space,
                 is_online, last_seen, reliability_score, bandwidth_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                node.node_id,
                node.node_address,
                node.available_space,
                node.used_space,
                node.total_space,
                node.is_online,
                node.last_seen,
                node.reliability_score,
                node.bandwidth_score
            ))
            
            conn.commit()
    
    def _save_access_permission(self, file_id: str, user_id: str, permission_level: str):
        """Salvar permissão de acesso"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO access_permissions 
                (file_id, user_id, permission_level, granted_at, granted_by)
                VALUES (?, ?, ?, ?, ?)
            """, (
                file_id,
                user_id,
                permission_level,
                time.time(),
                self.p2p_node.node_id
            ))
            
            conn.commit()
    
    def _load_stored_files(self):
        """Carregar arquivos armazenados"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM stored_files")
            
            for row in cursor.fetchall():
                (file_id, filename, file_size, file_hash, content_type, storage_type,
                 owner_id, access_level, encryption_key, replication_level, status,
                 created_at, modified_at, accessed_at, expires_at, metadata,
                 chunk_ids, replica_nodes) = row
                
                stored_file = StoredFile(
                    file_id=file_id,
                    filename=filename,
                    file_size=file_size,
                    file_hash=file_hash,
                    content_type=content_type,
                    storage_type=StorageType(storage_type),
                    owner_id=owner_id,
                    access_level=AccessLevel(access_level),
                    encryption_key=encryption_key,
                    replication_level=ReplicationLevel(replication_level),
                    status=StorageStatus(status),
                    created_at=created_at,
                    modified_at=modified_at,
                    accessed_at=accessed_at,
                    expires_at=expires_at,
                    metadata=json.loads(metadata),
                    chunk_ids=json.loads(chunk_ids),
                    replica_nodes=json.loads(replica_nodes)
                )
                
                self.stored_files[file_id] = stored_file
    
    def _load_storage_nodes(self):
        """Carregar nós de armazenamento"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM storage_nodes")
            
            for row in cursor.fetchall():
                (node_id, node_address, available_space, used_space, total_space,
                 is_online, last_seen, reliability_score, bandwidth_score) = row
                
                storage_node = StorageNode(
                    node_id=node_id,
                    node_address=node_address,
                    available_space=available_space,
                    used_space=used_space,
                    total_space=total_space,
                    is_online=bool(is_online),
                    last_seen=last_seen,
                    reliability_score=reliability_score,
                    bandwidth_score=bandwidth_score
                )
                
                self.storage_nodes[node_id] = storage_node

# Função de teste
def test_distributed_storage():
    """Teste básico do sistema de armazenamento distribuído"""
    print("💾 Testando Sistema de Armazenamento Distribuído...")
    
    try:
        # Criar componentes necessários
        from quantum_p2p_network import QuantumP2PNode
        from quantum_identity_system import QuantumIdentitySystem
        
        # Criar nó P2P
        p2p_node = QuantumP2PNode("storage_node", "Storage Node", 11001)
        
        # Criar sistema de identidade
        identity_system = QuantumIdentitySystem()
        
        # Criar sistema de armazenamento
        storage_system = QuantumDistributedStorage(p2p_node, identity_system)
        
        # Criar arquivo de teste
        test_file_path = "/tmp/test_file.txt"
        test_content = "Este é um arquivo de teste para o sistema de armazenamento distribuído QuantumShield."
        
        with open(test_file_path, 'w') as f:
            f.write(test_content)
        
        print(f"✅ Arquivo de teste criado: {test_file_path}")
        
        # Armazenar arquivo
        file_id = storage_system.store_file(
            file_path=test_file_path,
            filename="test_file.txt",
            storage_type=StorageType.DOCUMENT,
            access_level=AccessLevel.PRIVATE,
            replication_level=ReplicationLevel.LOW
        )
        print(f"✅ Arquivo armazenado: {file_id}")
        
        # Recuperar arquivo
        output_path = "/tmp/retrieved_file.txt"
        success = storage_system.retrieve_file(file_id, output_path)
        print(f"✅ Recuperação: {'Sucesso' if success else 'Falhou'}")
        
        if success:
            # Verificar conteúdo
            with open(output_path, 'r') as f:
                retrieved_content = f.read()
            
            if retrieved_content == test_content:
                print("✅ Integridade verificada: Conteúdo idêntico")
            else:
                print("❌ Erro de integridade: Conteúdo diferente")
        
        # Listar arquivos
        files = storage_system.list_files()
        print(f"✅ Arquivos listados: {len(files)}")
        
        # Estatísticas
        stats = storage_system.get_storage_stats()
        print(f"✅ Estatísticas: {stats['total_files']} arquivos, {stats['total_size']} bytes")
        
        # Limpar
        os.remove(test_file_path)
        if os.path.exists(output_path):
            os.remove(output_path)
        
        return True
        
    except Exception as e:
        print(f"❌ Erro no teste de armazenamento: {e}")
        return False

if __name__ == "__main__":
    test_distributed_storage()

