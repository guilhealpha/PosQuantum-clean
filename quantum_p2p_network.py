#!/usr/bin/env python3
"""
Quantum P2P Network Module - Simplified Version
Módulo de rede P2P quântica simplificado para resolver dependências

Autor: Manus AI
Data: 10 de Julho de 2025
Versão: 1.0 (POSSIBILIDADE-D)
"""

import socket
import threading
import time
import json
import hashlib
from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

class MessageType(Enum):
    """Tipos de mensagem P2P"""
    HANDSHAKE = "handshake"
    DATA = "data"
    PING = "ping"
    PONG = "pong"
    DISCONNECT = "disconnect"
    QUANTUM_KEY = "quantum_key"
    ENCRYPTED_MESSAGE = "encrypted_message"

@dataclass
class P2PMessage:
    """Estrutura de mensagem P2P"""
    message_type: MessageType
    sender_id: str
    recipient_id: str
    payload: Dict[str, Any]
    timestamp: float
    signature: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte mensagem para dicionário"""
        return {
            'message_type': self.message_type.value,
            'sender_id': self.sender_id,
            'recipient_id': self.recipient_id,
            'payload': self.payload,
            'timestamp': self.timestamp,
            'signature': self.signature
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'P2PMessage':
        """Cria mensagem a partir de dicionário"""
        return cls(
            message_type=MessageType(data['message_type']),
            sender_id=data['sender_id'],
            recipient_id=data['recipient_id'],
            payload=data['payload'],
            timestamp=data['timestamp'],
            signature=data.get('signature')
        )

@dataclass
class PeerInfo:
    """Informações de um peer"""
    peer_id: str
    address: str
    port: int
    public_key: Optional[str] = None
    last_seen: Optional[float] = None
    status: str = "unknown"

class PeerStatus(Enum):
    """Status de um peer"""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    ERROR = "error"

class QuantumP2PNode:
    """Nó P2P Quântico Simplificado"""
    
    def __init__(self, node_id: str = None, port: int = 8080):
        """Inicializa o nó P2P"""
        self.node_id = node_id or self._generate_node_id()
        self.port = port
        self.peers: Dict[str, PeerInfo] = {}
        self.message_handlers: Dict[MessageType, callable] = {}
        self.running = False
        self.server_socket = None
        self.server_thread = None
        
        # Configurar handlers padrão
        self._setup_default_handlers()
    
    def _generate_node_id(self) -> str:
        """Gera ID único para o nó"""
        return hashlib.sha256(f"{time.time()}_{socket.gethostname()}".encode()).hexdigest()[:16]
    
    def _setup_default_handlers(self):
        """Configura handlers padrão de mensagens"""
        self.message_handlers[MessageType.PING] = self._handle_ping
        self.message_handlers[MessageType.PONG] = self._handle_pong
        self.message_handlers[MessageType.HANDSHAKE] = self._handle_handshake
        self.message_handlers[MessageType.DISCONNECT] = self._handle_disconnect
    
    def start(self) -> bool:
        """Inicia o nó P2P"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(10)
            
            self.running = True
            self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
            self.server_thread.start()
            
            print(f"✅ Nó P2P {self.node_id} iniciado na porta {self.port}")
            return True
            
        except Exception as e:
            print(f"❌ Erro ao iniciar nó P2P: {e}")
            return False
    
    def stop(self):
        """Para o nó P2P"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print(f"🛑 Nó P2P {self.node_id} parado")
    
    def _server_loop(self):
        """Loop principal do servidor"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
            except Exception as e:
                if self.running:
                    print(f"⚠️ Erro no servidor P2P: {e}")
    
    def _handle_client(self, client_socket: socket.socket, address: tuple):
        """Manipula conexão de cliente"""
        try:
            while self.running:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                try:
                    message_data = json.loads(data.decode('utf-8'))
                    message = P2PMessage.from_dict(message_data)
                    self._process_message(message, client_socket)
                except json.JSONDecodeError:
                    print(f"⚠️ Mensagem inválida recebida de {address}")
                    
        except Exception as e:
            print(f"⚠️ Erro ao manipular cliente {address}: {e}")
        finally:
            client_socket.close()
    
    def _process_message(self, message: P2PMessage, client_socket: socket.socket):
        """Processa mensagem recebida"""
        handler = self.message_handlers.get(message.message_type)
        if handler:
            try:
                handler(message, client_socket)
            except Exception as e:
                print(f"⚠️ Erro ao processar mensagem {message.message_type}: {e}")
        else:
            print(f"⚠️ Handler não encontrado para {message.message_type}")
    
    def _handle_ping(self, message: P2PMessage, client_socket: socket.socket):
        """Manipula mensagem PING"""
        pong_message = P2PMessage(
            message_type=MessageType.PONG,
            sender_id=self.node_id,
            recipient_id=message.sender_id,
            payload={'timestamp': time.time()},
            timestamp=time.time()
        )
        self._send_message(pong_message, client_socket)
    
    def _handle_pong(self, message: P2PMessage, client_socket: socket.socket):
        """Manipula mensagem PONG"""
        print(f"📡 PONG recebido de {message.sender_id}")
    
    def _handle_handshake(self, message: P2PMessage, client_socket: socket.socket):
        """Manipula handshake"""
        peer_info = PeerInfo(
            peer_id=message.sender_id,
            address=client_socket.getpeername()[0],
            port=message.payload.get('port', 0),
            last_seen=time.time(),
            status=PeerStatus.CONNECTED.value
        )
        self.peers[message.sender_id] = peer_info
        print(f"🤝 Handshake com {message.sender_id}")
    
    def _handle_disconnect(self, message: P2PMessage, client_socket: socket.socket):
        """Manipula desconexão"""
        if message.sender_id in self.peers:
            self.peers[message.sender_id].status = PeerStatus.DISCONNECTED.value
        print(f"👋 Desconexão de {message.sender_id}")
    
    def _send_message(self, message: P2PMessage, client_socket: socket.socket):
        """Envia mensagem para cliente"""
        try:
            message_json = json.dumps(message.to_dict())
            client_socket.send(message_json.encode('utf-8'))
        except Exception as e:
            print(f"⚠️ Erro ao enviar mensagem: {e}")
    
    def connect_to_peer(self, address: str, port: int) -> bool:
        """Conecta a um peer"""
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((address, port))
            
            # Enviar handshake
            handshake = P2PMessage(
                message_type=MessageType.HANDSHAKE,
                sender_id=self.node_id,
                recipient_id="unknown",
                payload={'port': self.port},
                timestamp=time.time()
            )
            
            self._send_message(handshake, peer_socket)
            print(f"🔗 Conectado ao peer {address}:{port}")
            return True
            
        except Exception as e:
            print(f"❌ Erro ao conectar ao peer {address}:{port}: {e}")
            return False
    
    def send_data(self, peer_id: str, data: Dict[str, Any]) -> bool:
        """Envia dados para um peer"""
        if peer_id not in self.peers:
            print(f"⚠️ Peer {peer_id} não encontrado")
            return False
        
        try:
            peer = self.peers[peer_id]
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((peer.address, peer.port))
            
            message = P2PMessage(
                message_type=MessageType.DATA,
                sender_id=self.node_id,
                recipient_id=peer_id,
                payload=data,
                timestamp=time.time()
            )
            
            self._send_message(message, peer_socket)
            peer_socket.close()
            return True
            
        except Exception as e:
            print(f"❌ Erro ao enviar dados para {peer_id}: {e}")
            return False
    
    def get_peer_count(self) -> int:
        """Retorna número de peers conectados"""
        return len([p for p in self.peers.values() if p.status == PeerStatus.CONNECTED.value])
    
    def get_peers(self) -> List[PeerInfo]:
        """Retorna lista de peers"""
        return list(self.peers.values())
    
    def register_message_handler(self, message_type: MessageType, handler: callable):
        """Registra handler para tipo de mensagem"""
        self.message_handlers[message_type] = handler
    
    def ping_peer(self, peer_id: str) -> bool:
        """Envia PING para um peer"""
        return self.send_data(peer_id, {'type': 'ping'})

# Funções de compatibilidade
def create_p2p_node(node_id: str = None, port: int = 8080) -> QuantumP2PNode:
    """Cria um novo nó P2P"""
    return QuantumP2PNode(node_id, port)

def get_default_node() -> QuantumP2PNode:
    """Retorna nó padrão"""
    return QuantumP2PNode()

# Exportações principais
__all__ = [
    'QuantumP2PNode',
    'P2PMessage', 
    'MessageType',
    'PeerInfo',
    'PeerStatus',
    'create_p2p_node',
    'get_default_node'
]

if __name__ == "__main__":
    # Teste básico
    node = QuantumP2PNode("test_node", 8080)
    print(f"✅ Módulo quantum_p2p_network carregado com sucesso")
    print(f"📡 Nó de teste: {node.node_id}")

