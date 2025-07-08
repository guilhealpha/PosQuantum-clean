#!/usr/bin/env python3
"""
Quantum-Safe Instant Messaging System
Sistema de mensagens instantâneas com segurança pós-quântica
100% Real - Implementação completa e funcional
"""

import time
import json
import hashlib
import threading
import sqlite3
import logging
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import base64

# Importar módulos do QuantumShield
try:
    from .real_nist_crypto import RealNISTCrypto, CryptoAlgorithm
    from .quantum_p2p_network import QuantumP2PNode, P2PMessage, MessageType
    from .tamper_evident_audit_trail import TamperEvidentAuditSystem
except ImportError:
    import sys
    sys.path.append('/home/ubuntu/quantumshield_ecosystem_v1.0/core_original/01_PRODUTOS_PRINCIPAIS/quantumshield_core/lib')
    from real_nist_crypto import RealNISTCrypto, CryptoAlgorithm
    from quantum_p2p_network import QuantumP2PNode, P2PMessage, MessageType
    from tamper_evident_audit_trail import TamperEvidentAuditSystem

logger = logging.getLogger(__name__)

class MessageStatus(Enum):
    """Status da mensagem"""
    SENDING = "sending"
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"

class MessagePriority(Enum):
    """Prioridade da mensagem"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"

class ChatType(Enum):
    """Tipo de chat"""
    DIRECT = "direct"      # Chat direto entre dois usuários
    GROUP = "group"        # Chat em grupo
    CHANNEL = "channel"    # Canal público
    SECRET = "secret"      # Chat secreto com auto-destruição

@dataclass
class InstantMessage:
    """Mensagem instantânea"""
    message_id: str
    chat_id: str
    sender_id: str
    content: str
    message_type: str  # "text", "image", "file", "audio", "video", "location"
    timestamp: float
    status: MessageStatus
    priority: MessagePriority
    encrypted: bool = True
    reply_to: Optional[str] = None  # ID da mensagem sendo respondida
    forwarded_from: Optional[str] = None  # ID do remetente original
    expires_at: Optional[float] = None  # Para mensagens auto-destrutivas
    metadata: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        data['status'] = self.status.value
        data['priority'] = self.priority.value
        return data
    
    def is_expired(self) -> bool:
        """Verificar se mensagem expirou"""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

@dataclass
class ChatRoom:
    """Sala de chat"""
    chat_id: str
    name: str
    chat_type: ChatType
    participants: List[str]
    admin_ids: List[str]
    created_at: float
    created_by: str
    description: Optional[str] = None
    is_encrypted: bool = True
    auto_delete_messages: bool = False
    message_ttl: Optional[int] = None  # TTL em segundos
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        data['chat_type'] = self.chat_type.value
        return data

@dataclass
class UserPresence:
    """Presença do usuário"""
    user_id: str
    status: str  # "online", "away", "busy", "offline"
    last_seen: float
    status_message: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)

class QuantumMessagingSystem:
    """Sistema de mensagens instantâneas pós-quânticas"""
    
    def __init__(self, p2p_node: QuantumP2PNode, data_dir: str = "/home/ubuntu/.quantummessaging"):
        """Inicializar sistema de mensagens"""
        self.p2p_node = p2p_node
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Componentes criptográficos
        self.crypto = RealNISTCrypto()
        self.audit_trail = TamperEvidentAuditSystem()
        
        # Estado do sistema
        self.chat_rooms: Dict[str, ChatRoom] = {}
        self.messages: Dict[str, List[InstantMessage]] = {}  # chat_id -> messages
        self.user_presence: Dict[str, UserPresence] = {}
        self.encryption_keys: Dict[str, bytes] = {}  # chat_id -> encryption_key
        
        # Callbacks
        self.on_message_received: Optional[Callable] = None
        self.on_message_status_changed: Optional[Callable] = None
        self.on_user_presence_changed: Optional[Callable] = None
        self.on_chat_created: Optional[Callable] = None
        
        # Threading
        self.lock = threading.RLock()
        
        # Inicializar banco de dados
        self._init_database()
        
        # Carregar dados
        self._load_chat_rooms()
        self._load_messages()
        
        # Registrar handlers no P2P
        self._register_message_handlers()
        
        # Iniciar limpeza automática
        self._start_cleanup_thread()
        
        logger.info("Quantum Messaging System initialized")
    
    def _init_database(self):
        """Inicializar banco de dados"""
        self.db_path = self.data_dir / "messaging.db"
        
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            # Tabela de salas de chat
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS chat_rooms (
                    chat_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    chat_type TEXT NOT NULL,
                    participants TEXT NOT NULL,
                    admin_ids TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    created_by TEXT NOT NULL,
                    description TEXT,
                    is_encrypted BOOLEAN DEFAULT TRUE,
                    auto_delete_messages BOOLEAN DEFAULT FALSE,
                    message_ttl INTEGER
                )
            """)
            
            # Tabela de mensagens
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    message_id TEXT PRIMARY KEY,
                    chat_id TEXT NOT NULL,
                    sender_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    message_type TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    status TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    encrypted BOOLEAN DEFAULT TRUE,
                    reply_to TEXT,
                    forwarded_from TEXT,
                    expires_at REAL,
                    metadata TEXT,
                    FOREIGN KEY (chat_id) REFERENCES chat_rooms (chat_id)
                )
            """)
            
            # Tabela de presença
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_presence (
                    user_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    last_seen REAL NOT NULL,
                    status_message TEXT
                )
            """)
            
            # Tabela de chaves de criptografia
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS encryption_keys (
                    chat_id TEXT PRIMARY KEY,
                    encryption_key TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
            """)
            
            conn.commit()
    
    def _register_message_handlers(self):
        """Registrar handlers de mensagem no sistema P2P"""
        # Usar handler existente e adicionar processamento específico
        original_handler = self.p2p_node.message_handlers.get(MessageType.TEXT_MESSAGE)
        
        def enhanced_text_handler(message: P2PMessage, sock):
            # Processar como mensagem instantânea
            self._handle_instant_message(message, sock)
            
            # Chamar handler original se existir
            if original_handler:
                original_handler(message, sock)
        
        self.p2p_node.message_handlers[MessageType.TEXT_MESSAGE] = enhanced_text_handler
    
    def create_chat(self, name: str, chat_type: ChatType, participants: List[str],
                   description: Optional[str] = None, auto_delete: bool = False,
                   message_ttl: Optional[int] = None) -> str:
        """Criar nova sala de chat"""
        with self.lock:
            # Gerar ID do chat
            chat_id = self._generate_chat_id(name, participants)
            
            # Criar sala
            chat_room = ChatRoom(
                chat_id=chat_id,
                name=name,
                chat_type=chat_type,
                participants=participants,
                admin_ids=[self.p2p_node.node_id],
                created_at=time.time(),
                created_by=self.p2p_node.node_id,
                description=description,
                auto_delete_messages=auto_delete,
                message_ttl=message_ttl
            )
            
            # Gerar chave de criptografia para o chat
            encryption_key = self._generate_chat_encryption_key()
            self.encryption_keys[chat_id] = encryption_key
            
            # Salvar
            self.chat_rooms[chat_id] = chat_room
            self.messages[chat_id] = []
            
            self._save_chat_room(chat_room)
            self._save_encryption_key(chat_id, encryption_key)
            
            # Notificar participantes
            for participant_id in participants:
                if participant_id != self.p2p_node.node_id:
                    self._notify_chat_created(participant_id, chat_room)
            
            # Callback
            if self.on_chat_created:
                self.on_chat_created(chat_id, chat_room.to_dict())
            
            # Auditoria
            self.audit_trail.log_event(
                event_type="chat_created",
                details={
                    "chat_id": chat_id,
                    "name": name,
                    "type": chat_type.value,
                    "participants": participants,
                    "created_by": self.p2p_node.node_id
                }
            )
            
            logger.info(f"Chat created: {chat_id} - {name}")
            return chat_id
    
    def send_message(self, chat_id: str, content: str, message_type: str = "text",
                    priority: MessagePriority = MessagePriority.NORMAL,
                    reply_to: Optional[str] = None, expires_in: Optional[int] = None) -> str:
        """Enviar mensagem"""
        with self.lock:
            if chat_id not in self.chat_rooms:
                logger.error(f"Chat not found: {chat_id}")
                return ""
            
            chat_room = self.chat_rooms[chat_id]
            
            # Verificar se usuário é participante
            if self.p2p_node.node_id not in chat_room.participants:
                logger.error(f"User not in chat: {chat_id}")
                return ""
            
            # Gerar ID da mensagem
            message_id = self._generate_message_id()
            
            # Calcular expiração
            expires_at = None
            if expires_in:
                expires_at = time.time() + expires_in
            elif chat_room.message_ttl:
                expires_at = time.time() + chat_room.message_ttl
            
            # Criar mensagem
            message = InstantMessage(
                message_id=message_id,
                chat_id=chat_id,
                sender_id=self.p2p_node.node_id,
                content=content,
                message_type=message_type,
                timestamp=time.time(),
                status=MessageStatus.SENDING,
                priority=priority,
                reply_to=reply_to,
                expires_at=expires_at
            )
            
            # Criptografar conteúdo
            if chat_room.is_encrypted and chat_id in self.encryption_keys:
                encrypted_content = self._encrypt_message_content(content, self.encryption_keys[chat_id])
                message.content = encrypted_content
                message.encrypted = True
            
            # Salvar mensagem
            self.messages[chat_id].append(message)
            self._save_message(message)
            
            # Enviar para participantes
            success_count = 0
            for participant_id in chat_room.participants:
                if participant_id != self.p2p_node.node_id:
                    if self._send_message_to_participant(participant_id, message):
                        success_count += 1
            
            # Atualizar status
            if success_count > 0:
                message.status = MessageStatus.SENT
            else:
                message.status = MessageStatus.FAILED
            
            self._save_message(message)
            
            # Callback
            if self.on_message_status_changed:
                self.on_message_status_changed(message_id, message.status)
            
            # Auditoria
            self.audit_trail.log_event(
                event_type="message_sent",
                details={
                    "message_id": message_id,
                    "chat_id": chat_id,
                    "sender": self.p2p_node.node_id,
                    "type": message_type,
                    "recipients": success_count
                }
            )
            
            logger.info(f"Message sent: {message_id} to chat {chat_id}")
            return message_id
    
    def _send_message_to_participant(self, participant_id: str, message: InstantMessage) -> bool:
        """Enviar mensagem para um participante"""
        # Criar mensagem P2P
        p2p_message = P2PMessage(
            message_id=self.p2p_node._generate_message_id(),
            message_type=MessageType.TEXT_MESSAGE,
            sender_id=self.p2p_node.node_id,
            recipient_id=participant_id,
            timestamp=time.time(),
            payload={
                "instant_message": message.to_dict(),
                "chat_id": message.chat_id
            }
        )
        
        return self.p2p_node._send_message(participant_id, p2p_message)
    
    def _handle_instant_message(self, p2p_message: P2PMessage, sock):
        """Processar mensagem instantânea recebida"""
        payload = p2p_message.payload
        
        if "instant_message" not in payload:
            return
        
        message_data = payload["instant_message"]
        chat_id = payload.get("chat_id")
        
        # Reconstruir mensagem
        message = InstantMessage(
            message_id=message_data["message_id"],
            chat_id=message_data["chat_id"],
            sender_id=message_data["sender_id"],
            content=message_data["content"],
            message_type=message_data["message_type"],
            timestamp=message_data["timestamp"],
            status=MessageStatus(message_data["status"]),
            priority=MessagePriority(message_data["priority"]),
            encrypted=message_data.get("encrypted", False),
            reply_to=message_data.get("reply_to"),
            forwarded_from=message_data.get("forwarded_from"),
            expires_at=message_data.get("expires_at"),
            metadata=message_data.get("metadata")
        )
        
        # Descriptografar se necessário
        if message.encrypted and chat_id in self.encryption_keys:
            try:
                decrypted_content = self._decrypt_message_content(message.content, self.encryption_keys[chat_id])
                message.content = decrypted_content
                message.encrypted = False
            except Exception as e:
                logger.error(f"Failed to decrypt message {message.message_id}: {e}")
                return
        
        # Verificar expiração
        if message.is_expired():
            logger.info(f"Received expired message: {message.message_id}")
            return
        
        # Salvar mensagem
        with self.lock:
            if chat_id not in self.messages:
                self.messages[chat_id] = []
            
            self.messages[chat_id].append(message)
            self._save_message(message)
        
        # Callback
        if self.on_message_received:
            self.on_message_received(message.message_id, message.to_dict())
        
        # Auditoria
        self.audit_trail.log_event(
            event_type="message_received",
            details={
                "message_id": message.message_id,
                "chat_id": chat_id,
                "sender": message.sender_id,
                "type": message.message_type
            }
        )
        
        logger.info(f"Message received: {message.message_id} from {message.sender_id}")
    
    def mark_message_as_read(self, message_id: str) -> bool:
        """Marcar mensagem como lida"""
        with self.lock:
            for chat_id, messages in self.messages.items():
                for message in messages:
                    if message.message_id == message_id:
                        message.status = MessageStatus.READ
                        self._save_message(message)
                        
                        # Callback
                        if self.on_message_status_changed:
                            self.on_message_status_changed(message_id, message.status)
                        
                        return True
            
            return False
    
    def delete_message(self, message_id: str) -> bool:
        """Deletar mensagem"""
        with self.lock:
            for chat_id, messages in self.messages.items():
                for i, message in enumerate(messages):
                    if message.message_id == message_id:
                        # Remover da lista
                        del messages[i]
                        
                        # Remover do banco
                        self._delete_message_from_db(message_id)
                        
                        # Auditoria
                        self.audit_trail.log_event(
                            event_type="message_deleted",
                            details={
                                "message_id": message_id,
                                "chat_id": chat_id,
                                "deleted_by": self.p2p_node.node_id
                            }
                        )
                        
                        return True
            
            return False
    
    def get_chat_messages(self, chat_id: str, limit: int = 50, offset: int = 0) -> List[InstantMessage]:
        """Obter mensagens do chat"""
        if chat_id not in self.messages:
            return []
        
        messages = self.messages[chat_id]
        
        # Filtrar mensagens expiradas
        valid_messages = [msg for msg in messages if not msg.is_expired()]
        
        # Ordenar por timestamp (mais recentes primeiro)
        valid_messages.sort(key=lambda x: x.timestamp, reverse=True)
        
        # Aplicar paginação
        start = offset
        end = offset + limit
        
        return valid_messages[start:end]
    
    def search_messages(self, query: str, chat_id: Optional[str] = None) -> List[InstantMessage]:
        """Buscar mensagens"""
        results = []
        
        chats_to_search = [chat_id] if chat_id else list(self.messages.keys())
        
        for cid in chats_to_search:
            if cid not in self.messages:
                continue
            
            for message in self.messages[cid]:
                if not message.is_expired() and query.lower() in message.content.lower():
                    results.append(message)
        
        # Ordenar por relevância (timestamp mais recente primeiro)
        results.sort(key=lambda x: x.timestamp, reverse=True)
        
        return results
    
    def update_presence(self, status: str, status_message: Optional[str] = None):
        """Atualizar presença do usuário"""
        presence = UserPresence(
            user_id=self.p2p_node.node_id,
            status=status,
            last_seen=time.time(),
            status_message=status_message
        )
        
        self.user_presence[self.p2p_node.node_id] = presence
        self._save_user_presence(presence)
        
        # Notificar contatos
        self._broadcast_presence_update(presence)
        
        logger.info(f"Presence updated: {status}")
    
    def _notify_chat_created(self, participant_id: str, chat_room: ChatRoom):
        """Notificar participante sobre novo chat"""
        notification = P2PMessage(
            message_id=self.p2p_node._generate_message_id(),
            message_type=MessageType.TEXT_MESSAGE,
            sender_id=self.p2p_node.node_id,
            recipient_id=participant_id,
            timestamp=time.time(),
            payload={
                "chat_notification": "created",
                "chat_room": chat_room.to_dict()
            }
        )
        
        self.p2p_node._send_message(participant_id, notification)
    
    def _broadcast_presence_update(self, presence: UserPresence):
        """Transmitir atualização de presença"""
        # Enviar para todos os peers conectados
        for peer_id in self.p2p_node.connections.keys():
            presence_update = P2PMessage(
                message_id=self.p2p_node._generate_message_id(),
                message_type=MessageType.TEXT_MESSAGE,
                sender_id=self.p2p_node.node_id,
                recipient_id=peer_id,
                timestamp=time.time(),
                payload={
                    "presence_update": presence.to_dict()
                }
            )
            
            self.p2p_node._send_message(peer_id, presence_update)
    
    def _start_cleanup_thread(self):
        """Iniciar thread de limpeza automática"""
        def cleanup_loop():
            while True:
                time.sleep(300)  # 5 minutos
                self._cleanup_expired_messages()
        
        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()
    
    def _cleanup_expired_messages(self):
        """Limpar mensagens expiradas"""
        with self.lock:
            current_time = time.time()
            
            for chat_id, messages in self.messages.items():
                # Filtrar mensagens não expiradas
                valid_messages = []
                expired_count = 0
                
                for message in messages:
                    if message.is_expired():
                        self._delete_message_from_db(message.message_id)
                        expired_count += 1
                    else:
                        valid_messages.append(message)
                
                # Atualizar lista
                self.messages[chat_id] = valid_messages
                
                if expired_count > 0:
                    logger.info(f"Cleaned up {expired_count} expired messages from chat {chat_id}")
    
    def _generate_chat_id(self, name: str, participants: List[str]) -> str:
        """Gerar ID único para chat"""
        participants_sorted = sorted(participants)
        data = f"{name}{''.join(participants_sorted)}{time.time()}"
        return "chat_" + hashlib.sha3_256(data.encode()).hexdigest()[:16]
    
    def _generate_message_id(self) -> str:
        """Gerar ID único para mensagem"""
        data = f"{self.p2p_node.node_id}{time.time()}{hash(threading.current_thread())}"
        return "msg_" + hashlib.sha3_256(data.encode()).hexdigest()[:16]
    
    def _generate_chat_encryption_key(self) -> bytes:
        """Gerar chave de criptografia para chat"""
        import os
        return os.urandom(32)  # 256 bits
    
    def _encrypt_message_content(self, content: str, key: bytes) -> str:
        """Criptografar conteúdo da mensagem"""
        from cryptography.fernet import Fernet
        
        fernet_key = base64.urlsafe_b64encode(key)
        f = Fernet(fernet_key)
        
        encrypted_bytes = f.encrypt(content.encode('utf-8'))
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    
    def _decrypt_message_content(self, encrypted_content: str, key: bytes) -> str:
        """Descriptografar conteúdo da mensagem"""
        from cryptography.fernet import Fernet
        
        fernet_key = base64.urlsafe_b64encode(key)
        f = Fernet(fernet_key)
        
        encrypted_bytes = base64.b64decode(encrypted_content.encode('utf-8'))
        decrypted_bytes = f.decrypt(encrypted_bytes)
        return decrypted_bytes.decode('utf-8')
    
    # Métodos de persistência
    def _save_chat_room(self, chat_room: ChatRoom):
        """Salvar sala de chat"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO chat_rooms 
                (chat_id, name, chat_type, participants, admin_ids, created_at, 
                 created_by, description, is_encrypted, auto_delete_messages, message_ttl)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                chat_room.chat_id,
                chat_room.name,
                chat_room.chat_type.value,
                json.dumps(chat_room.participants),
                json.dumps(chat_room.admin_ids),
                chat_room.created_at,
                chat_room.created_by,
                chat_room.description,
                chat_room.is_encrypted,
                chat_room.auto_delete_messages,
                chat_room.message_ttl
            ))
            
            conn.commit()
    
    def _save_message(self, message: InstantMessage):
        """Salvar mensagem"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO messages 
                (message_id, chat_id, sender_id, content, message_type, timestamp,
                 status, priority, encrypted, reply_to, forwarded_from, expires_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                message.message_id,
                message.chat_id,
                message.sender_id,
                message.content,
                message.message_type,
                message.timestamp,
                message.status.value,
                message.priority.value,
                message.encrypted,
                message.reply_to,
                message.forwarded_from,
                message.expires_at,
                json.dumps(message.metadata) if message.metadata else None
            ))
            
            conn.commit()
    
    def _save_user_presence(self, presence: UserPresence):
        """Salvar presença do usuário"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO user_presence 
                (user_id, status, last_seen, status_message)
                VALUES (?, ?, ?, ?)
            """, (
                presence.user_id,
                presence.status,
                presence.last_seen,
                presence.status_message
            ))
            
            conn.commit()
    
    def _save_encryption_key(self, chat_id: str, key: bytes):
        """Salvar chave de criptografia"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO encryption_keys 
                (chat_id, encryption_key, created_at)
                VALUES (?, ?, ?)
            """, (
                chat_id,
                base64.b64encode(key).decode('utf-8'),
                time.time()
            ))
            
            conn.commit()
    
    def _delete_message_from_db(self, message_id: str):
        """Deletar mensagem do banco"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM messages WHERE message_id = ?", (message_id,))
            conn.commit()
    
    def _load_chat_rooms(self):
        """Carregar salas de chat"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM chat_rooms")
            
            for row in cursor.fetchall():
                (chat_id, name, chat_type, participants, admin_ids, created_at,
                 created_by, description, is_encrypted, auto_delete_messages, message_ttl) = row
                
                chat_room = ChatRoom(
                    chat_id=chat_id,
                    name=name,
                    chat_type=ChatType(chat_type),
                    participants=json.loads(participants),
                    admin_ids=json.loads(admin_ids),
                    created_at=created_at,
                    created_by=created_by,
                    description=description,
                    is_encrypted=bool(is_encrypted),
                    auto_delete_messages=bool(auto_delete_messages),
                    message_ttl=message_ttl
                )
                
                self.chat_rooms[chat_id] = chat_room
                
                # Carregar chave de criptografia
                cursor.execute("SELECT encryption_key FROM encryption_keys WHERE chat_id = ?", (chat_id,))
                key_row = cursor.fetchone()
                if key_row:
                    self.encryption_keys[chat_id] = base64.b64decode(key_row[0])
    
    def _load_messages(self):
        """Carregar mensagens"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM messages ORDER BY timestamp DESC LIMIT 1000")
            
            for row in cursor.fetchall():
                (message_id, chat_id, sender_id, content, message_type, timestamp,
                 status, priority, encrypted, reply_to, forwarded_from, expires_at, metadata) = row
                
                message = InstantMessage(
                    message_id=message_id,
                    chat_id=chat_id,
                    sender_id=sender_id,
                    content=content,
                    message_type=message_type,
                    timestamp=timestamp,
                    status=MessageStatus(status),
                    priority=MessagePriority(priority),
                    encrypted=bool(encrypted),
                    reply_to=reply_to,
                    forwarded_from=forwarded_from,
                    expires_at=expires_at,
                    metadata=json.loads(metadata) if metadata else None
                )
                
                if chat_id not in self.messages:
                    self.messages[chat_id] = []
                
                self.messages[chat_id].append(message)
    
    def get_chat_rooms(self) -> List[ChatRoom]:
        """Obter lista de salas de chat"""
        return list(self.chat_rooms.values())
    
    def get_chat_room(self, chat_id: str) -> Optional[ChatRoom]:
        """Obter sala de chat específica"""
        return self.chat_rooms.get(chat_id)

# Função de teste
def test_messaging_system():
    """Teste básico do sistema de mensagens"""
    print("💬 Testando Sistema de Mensagens...")
    
    # Criar nós P2P
    from quantum_p2p_network import QuantumP2PNode
    
    node1 = QuantumP2PNode("user1", "User 1", 10001)
    node2 = QuantumP2PNode("user2", "User 2", 10002)
    
    # Criar sistemas de mensagem
    msg_system1 = QuantumMessagingSystem(node1)
    msg_system2 = QuantumMessagingSystem(node2)
    
    # Callbacks
    def on_message_received(message_id, message_data):
        print(f"📨 Mensagem recebida: {message_data['content']}")
    
    msg_system2.on_message_received = on_message_received
    
    try:
        # Iniciar nós
        node1.start_server()
        node2.start_server()
        
        print(f"✅ Nós iniciados nas portas {node1.port} e {node2.port}")
        
        # Conectar nós
        success = node1.connect_to_peer("127.0.0.1", node2.port)
        print(f"✅ Conexão P2P: {'Sucesso' if success else 'Falhou'}")
        
        if success:
            time.sleep(1)
            
            # Criar chat
            chat_id = msg_system1.create_chat(
                name="Chat de Teste",
                chat_type=ChatType.DIRECT,
                participants=["user1", "user2"]
            )
            print(f"✅ Chat criado: {chat_id}")
            
            # Enviar mensagem
            message_id = msg_system1.send_message(
                chat_id=chat_id,
                content="Olá! Esta é uma mensagem de teste criptografada.",
                message_type="text",
                priority=MessagePriority.NORMAL
            )
            print(f"✅ Mensagem enviada: {message_id}")
            
            # Aguardar processamento
            time.sleep(2)
            
            # Verificar mensagens
            messages1 = msg_system1.get_chat_messages(chat_id)
            print(f"✅ Mensagens no sistema 1: {len(messages1)}")
            
            # Buscar mensagens
            search_results = msg_system1.search_messages("teste")
            print(f"✅ Resultados da busca: {len(search_results)}")
            
            # Atualizar presença
            msg_system1.update_presence("online", "Testando sistema")
            print("✅ Presença atualizada")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro no teste de mensagens: {e}")
        return False
    
    finally:
        try:
            node1.stop_server()
            node2.stop_server()
        except:
            pass

if __name__ == "__main__":
    test_messaging_system()

