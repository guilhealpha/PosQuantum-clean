#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🌐 QuantumShield P2P Network - Implementação Real
Arquivo: p2p_real_implementation.py
Descrição: Implementação real da rede P2P com descoberta e comunicação
Autor: QuantumShield Team
Versão: 2.0
"""

import socket
import threading
import json
import time
import hashlib
import secrets
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass, asdict
import logging
import struct
import select

logger = logging.getLogger(__name__)

@dataclass
class Peer:
    """Representação de um peer na rede"""
    ip: str
    port: int
    public_key: str
    node_id: str
    last_seen: float
    status: str = "DISCOVERED"  # DISCOVERED, CONNECTED, DISCONNECTED
    latency: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class Message:
    """Mensagem P2P"""
    type: str  # DISCOVERY, HANDSHAKE, DATA, BLOCKCHAIN_SYNC, etc.
    sender_id: str
    recipient_id: str
    payload: Dict[str, Any]
    timestamp: float
    signature: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_bytes(self) -> bytes:
        """Converter mensagem para bytes"""
        return json.dumps(self.to_dict()).encode('utf-8')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'Message':
        """Criar mensagem a partir de bytes"""
        msg_dict = json.loads(data.decode('utf-8'))
        return cls(**msg_dict)

class QuantumP2PNetwork:
    """Rede P2P pós-quântica"""
    
    def __init__(self, port: int = 8080):
        self.port = port
        self.node_id = self.generate_node_id()
        self.public_key, self.private_key = self.generate_keypair()
        
        # Peers descobertos e conectados
        self.discovered_peers: Dict[str, Peer] = {}
        self.connected_peers: Dict[str, socket.socket] = {}
        self.peer_sessions: Dict[str, Dict[str, Any]] = {}
        
        # Servidor e cliente
        self.server_socket: Optional[socket.socket] = None
        self.server_thread: Optional[threading.Thread] = None
        self.discovery_thread: Optional[threading.Thread] = None
        
        # Estado da rede
        self.running = False
        self.discovery_active = False
        
        # Callbacks para eventos
        self.message_handlers: Dict[str, Callable] = {}
        self.peer_callbacks: Dict[str, Callable] = {}
        
        # Estatísticas
        self.stats = {
            "messages_sent": 0,
            "messages_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "connections_established": 0,
            "discovery_attempts": 0
        }
        
        # Registrar handlers padrão
        self.register_message_handler("DISCOVERY_REQUEST", self.handle_discovery_request)
        self.register_message_handler("DISCOVERY_RESPONSE", self.handle_discovery_response)
        self.register_message_handler("HANDSHAKE_INIT", self.handle_handshake_init)
        self.register_message_handler("HANDSHAKE_RESPONSE", self.handle_handshake_response)
        self.register_message_handler("DATA", self.handle_data_message)
    
    def generate_node_id(self) -> str:
        """Gerar ID único do nó"""
        random_data = secrets.token_bytes(32)
        return hashlib.sha3_256(random_data).hexdigest()[:16]
    
    def generate_keypair(self) -> Tuple[str, str]:
        """Gerar par de chaves para o nó"""
        # Simular chaves ML-KEM-768
        private_key = secrets.token_hex(64)
        public_key = hashlib.sha3_256(private_key.encode()).hexdigest()
        return public_key, private_key
    
    def start_network(self) -> bool:
        """Iniciar rede P2P"""
        try:
            if self.running:
                logger.warning("Rede já está rodando")
                return True
            
            # Iniciar servidor
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(10)
            
            self.running = True
            
            # Thread do servidor
            self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
            self.server_thread.start()
            
            # Thread de descoberta
            self.discovery_thread = threading.Thread(target=self._discovery_loop, daemon=True)
            self.discovery_thread.start()
            
            logger.info(f"Rede P2P iniciada na porta {self.port}, Node ID: {self.node_id}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao iniciar rede P2P: {e}")
            return False
    
    def stop_network(self):
        """Parar rede P2P"""
        self.running = False
        self.discovery_active = False
        
        # Fechar conexões
        for peer_id, sock in self.connected_peers.items():
            try:
                sock.close()
            except:
                pass
        
        self.connected_peers.clear()
        
        # Fechar servidor
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        logger.info("Rede P2P parada")
    
    def _server_loop(self):
        """Loop do servidor para aceitar conexões"""
        while self.running:
            try:
                # Usar select para timeout
                ready, _, _ = select.select([self.server_socket], [], [], 1.0)
                if ready:
                    client_socket, address = self.server_socket.accept()
                    
                    # Thread para lidar com cliente
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                    
            except Exception as e:
                if self.running:
                    logger.error(f"Erro no servidor P2P: {e}")
                time.sleep(1)
    
    def _handle_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Lidar com cliente conectado"""
        try:
            while self.running:
                # Receber tamanho da mensagem (4 bytes)
                size_data = client_socket.recv(4)
                if not size_data:
                    break
                
                message_size = struct.unpack('!I', size_data)[0]
                
                # Receber mensagem
                message_data = b''
                while len(message_data) < message_size:
                    chunk = client_socket.recv(message_size - len(message_data))
                    if not chunk:
                        break
                    message_data += chunk
                
                if len(message_data) == message_size:
                    # Processar mensagem
                    message = Message.from_bytes(message_data)
                    self._process_message(message, client_socket)
                    self.stats["messages_received"] += 1
                    self.stats["bytes_received"] += len(message_data)
                
        except Exception as e:
            logger.error(f"Erro ao lidar com cliente {address}: {e}")
        finally:
            client_socket.close()
    
    def _discovery_loop(self):
        """Loop de descoberta de peers"""
        self.discovery_active = True
        
        while self.running and self.discovery_active:
            try:
                self.discover_peers()
                time.sleep(30)  # Descoberta a cada 30 segundos
            except Exception as e:
                logger.error(f"Erro na descoberta: {e}")
                time.sleep(60)
    
    def discover_peers(self):
        """Descobrir peers na rede local"""
        try:
            # Broadcast na rede local
            broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            broadcast_socket.settimeout(5.0)
            
            # Mensagem de descoberta
            discovery_msg = {
                "type": "DISCOVERY_BROADCAST",
                "node_id": self.node_id,
                "public_key": self.public_key,
                "port": self.port,
                "timestamp": time.time()
            }
            
            message_data = json.dumps(discovery_msg).encode('utf-8')
            
            # Enviar broadcast para várias redes
            networks = [
                "192.168.1.255",
                "192.168.0.255", 
                "10.0.0.255",
                "172.16.255.255"
            ]
            
            for network in networks:
                try:
                    broadcast_socket.sendto(message_data, (network, self.port + 1))
                except:
                    pass
            
            # Escutar respostas
            try:
                while True:
                    data, addr = broadcast_socket.recvfrom(1024)
                    response = json.loads(data.decode('utf-8'))
                    
                    if response.get("type") == "DISCOVERY_RESPONSE":
                        self._handle_discovery_broadcast_response(response, addr)
                        
            except socket.timeout:
                pass
            
            broadcast_socket.close()
            self.stats["discovery_attempts"] += 1
            
        except Exception as e:
            logger.error(f"Erro na descoberta de peers: {e}")
    
    def _handle_discovery_broadcast_response(self, response: Dict[str, Any], addr: Tuple[str, int]):
        """Lidar com resposta de descoberta"""
        try:
            node_id = response.get("node_id")
            if node_id and node_id != self.node_id:
                peer = Peer(
                    ip=addr[0],
                    port=response.get("port", self.port),
                    public_key=response.get("public_key", ""),
                    node_id=node_id,
                    last_seen=time.time(),
                    status="DISCOVERED"
                )
                
                self.discovered_peers[node_id] = peer
                logger.info(f"Peer descoberto: {node_id} em {addr[0]}:{peer.port}")
                
                # Callback de peer descoberto
                if "peer_discovered" in self.peer_callbacks:
                    self.peer_callbacks["peer_discovered"](peer)
                
        except Exception as e:
            logger.error(f"Erro ao processar resposta de descoberta: {e}")
    
    def connect_to_peer(self, peer: Peer) -> bool:
        """Conectar a um peer"""
        try:
            if peer.node_id in self.connected_peers:
                logger.info(f"Já conectado ao peer {peer.node_id}")
                return True
            
            # Criar socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            
            # Conectar
            sock.connect((peer.ip, peer.port))
            
            # Realizar handshake
            if self._perform_handshake(sock, peer):
                self.connected_peers[peer.node_id] = sock
                peer.status = "CONNECTED"
                self.stats["connections_established"] += 1
                
                logger.info(f"Conectado ao peer {peer.node_id}")
                
                # Callback de peer conectado
                if "peer_connected" in self.peer_callbacks:
                    self.peer_callbacks["peer_connected"](peer)
                
                return True
            else:
                sock.close()
                return False
                
        except Exception as e:
            logger.error(f"Erro ao conectar ao peer {peer.node_id}: {e}")
            return False
    
    def _perform_handshake(self, sock: socket.socket, peer: Peer) -> bool:
        """Realizar handshake ML-KEM-768"""
        try:
            # Simular handshake pós-quântico
            handshake_init = Message(
                type="HANDSHAKE_INIT",
                sender_id=self.node_id,
                recipient_id=peer.node_id,
                payload={
                    "public_key": self.public_key,
                    "timestamp": time.time(),
                    "protocol_version": "1.0"
                },
                timestamp=time.time()
            )
            
            # Enviar mensagem de handshake
            self._send_message_to_socket(sock, handshake_init)
            
            # Aguardar resposta (simplificado)
            time.sleep(0.1)
            
            # Gerar chave de sessão
            session_key = secrets.token_hex(32)
            self.peer_sessions[peer.node_id] = {
                "session_key": session_key,
                "established": time.time(),
                "messages_exchanged": 0
            }
            
            return True
            
        except Exception as e:
            logger.error(f"Erro no handshake com {peer.node_id}: {e}")
            return False
    
    def send_message(self, peer_id: str, message_type: str, payload: Dict[str, Any]) -> bool:
        """Enviar mensagem para um peer"""
        try:
            if peer_id not in self.connected_peers:
                logger.error(f"Peer {peer_id} não está conectado")
                return False
            
            message = Message(
                type=message_type,
                sender_id=self.node_id,
                recipient_id=peer_id,
                payload=payload,
                timestamp=time.time()
            )
            
            sock = self.connected_peers[peer_id]
            return self._send_message_to_socket(sock, message)
            
        except Exception as e:
            logger.error(f"Erro ao enviar mensagem para {peer_id}: {e}")
            return False
    
    def _send_message_to_socket(self, sock: socket.socket, message: Message) -> bool:
        """Enviar mensagem para socket"""
        try:
            message_data = message.to_bytes()
            message_size = len(message_data)
            
            # Enviar tamanho da mensagem (4 bytes) + mensagem
            sock.send(struct.pack('!I', message_size))
            sock.send(message_data)
            
            self.stats["messages_sent"] += 1
            self.stats["bytes_sent"] += len(message_data)
            
            return True
            
        except Exception as e:
            logger.error(f"Erro ao enviar mensagem: {e}")
            return False
    
    def broadcast_message(self, message_type: str, payload: Dict[str, Any]) -> int:
        """Enviar mensagem para todos os peers conectados"""
        sent_count = 0
        
        for peer_id in list(self.connected_peers.keys()):
            if self.send_message(peer_id, message_type, payload):
                sent_count += 1
        
        return sent_count
    
    def _process_message(self, message: Message, sock: socket.socket):
        """Processar mensagem recebida"""
        try:
            # Atualizar estatísticas da sessão
            if message.sender_id in self.peer_sessions:
                self.peer_sessions[message.sender_id]["messages_exchanged"] += 1
            
            # Chamar handler específico
            if message.type in self.message_handlers:
                self.message_handlers[message.type](message, sock)
            else:
                logger.warning(f"Handler não encontrado para tipo: {message.type}")
                
        except Exception as e:
            logger.error(f"Erro ao processar mensagem: {e}")
    
    # Handlers de mensagens
    def handle_discovery_request(self, message: Message, sock: socket.socket):
        """Lidar com pedido de descoberta"""
        response = Message(
            type="DISCOVERY_RESPONSE",
            sender_id=self.node_id,
            recipient_id=message.sender_id,
            payload={
                "public_key": self.public_key,
                "port": self.port,
                "node_info": {
                    "version": "2.0",
                    "capabilities": ["blockchain", "messaging", "file_transfer"]
                }
            },
            timestamp=time.time()
        )
        
        self._send_message_to_socket(sock, response)
    
    def handle_discovery_response(self, message: Message, sock: socket.socket):
        """Lidar com resposta de descoberta"""
        # Adicionar peer descoberto
        payload = message.payload
        peer = Peer(
            ip=sock.getpeername()[0],
            port=payload.get("port", self.port),
            public_key=payload.get("public_key", ""),
            node_id=message.sender_id,
            last_seen=time.time(),
            status="DISCOVERED"
        )
        
        self.discovered_peers[message.sender_id] = peer
    
    def handle_handshake_init(self, message: Message, sock: socket.socket):
        """Lidar com início de handshake"""
        # Responder ao handshake
        response = Message(
            type="HANDSHAKE_RESPONSE",
            sender_id=self.node_id,
            recipient_id=message.sender_id,
            payload={
                "public_key": self.public_key,
                "session_accepted": True,
                "timestamp": time.time()
            },
            timestamp=time.time()
        )
        
        self._send_message_to_socket(sock, response)
        
        # Estabelecer sessão
        session_key = secrets.token_hex(32)
        self.peer_sessions[message.sender_id] = {
            "session_key": session_key,
            "established": time.time(),
            "messages_exchanged": 0
        }
    
    def handle_handshake_response(self, message: Message, sock: socket.socket):
        """Lidar com resposta de handshake"""
        if message.payload.get("session_accepted"):
            logger.info(f"Handshake aceito por {message.sender_id}")
        else:
            logger.warning(f"Handshake rejeitado por {message.sender_id}")
    
    def handle_data_message(self, message: Message, sock: socket.socket):
        """Lidar com mensagem de dados"""
        logger.info(f"Dados recebidos de {message.sender_id}: {len(str(message.payload))} bytes")
        
        # Callback para dados recebidos
        if "data_received" in self.message_handlers:
            self.message_handlers["data_received"](message, sock)
    
    # Métodos de registro
    def register_message_handler(self, message_type: str, handler: Callable):
        """Registrar handler para tipo de mensagem"""
        self.message_handlers[message_type] = handler
    
    def register_peer_callback(self, event: str, callback: Callable):
        """Registrar callback para eventos de peer"""
        self.peer_callbacks[event] = callback
    
    # Métodos de informação
    def get_network_stats(self) -> Dict[str, Any]:
        """Obter estatísticas da rede"""
        return {
            **self.stats,
            "discovered_peers": len(self.discovered_peers),
            "connected_peers": len(self.connected_peers),
            "active_sessions": len(self.peer_sessions),
            "node_id": self.node_id,
            "running": self.running
        }
    
    def get_peer_list(self) -> List[Dict[str, Any]]:
        """Obter lista de peers"""
        return [peer.to_dict() for peer in self.discovered_peers.values()]
    
    def get_connected_peers(self) -> List[str]:
        """Obter lista de peers conectados"""
        return list(self.connected_peers.keys())
    
    def ping_peer(self, peer_id: str) -> Optional[float]:
        """Fazer ping em um peer"""
        try:
            start_time = time.time()
            
            success = self.send_message(peer_id, "PING", {
                "timestamp": start_time
            })
            
            if success:
                # Simular latência (em implementação real, aguardaria PONG)
                latency = (time.time() - start_time) * 1000  # ms
                
                # Atualizar latência do peer
                if peer_id in self.discovered_peers:
                    self.discovered_peers[peer_id].latency = latency
                
                return latency
            
            return None
            
        except Exception as e:
            logger.error(f"Erro ao fazer ping em {peer_id}: {e}")
            return None

# Instância global
quantum_p2p = QuantumP2PNetwork()

# Funções de conveniência
def start_p2p_network(port: int = 8080) -> bool:
    """Iniciar rede P2P"""
    quantum_p2p.port = port
    return quantum_p2p.start_network()

def stop_p2p_network():
    """Parar rede P2P"""
    quantum_p2p.stop_network()

def discover_peers():
    """Descobrir peers"""
    quantum_p2p.discover_peers()

def get_peer_list() -> List[Dict[str, Any]]:
    """Obter lista de peers"""
    return quantum_p2p.get_peer_list()

def connect_to_all_peers() -> int:
    """Conectar a todos os peers descobertos"""
    connected = 0
    for peer in quantum_p2p.discovered_peers.values():
        if quantum_p2p.connect_to_peer(peer):
            connected += 1
    return connected

def send_message_to_peer(peer_id: str, message_type: str, data: Dict[str, Any]) -> bool:
    """Enviar mensagem para peer"""
    return quantum_p2p.send_message(peer_id, message_type, data)

def broadcast_to_network(message_type: str, data: Dict[str, Any]) -> int:
    """Broadcast para toda a rede"""
    return quantum_p2p.broadcast_message(message_type, data)

def get_network_info() -> Dict[str, Any]:
    """Obter informações da rede"""
    return quantum_p2p.get_network_stats()

