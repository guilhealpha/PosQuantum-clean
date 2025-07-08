#!/usr/bin/env python3
"""
🛡️ QuantumShield - NAT Traversal System
Arquivo: quantum_nat_traversal.py
Descrição: Sistema NAT Traversal com STUN/TURN para conectividade P2P
Autor: QuantumShield Team
Versão: 2.0
Data: 03/07/2025
"""

import socket
import struct
import random
import time
import threading
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class STUNMessageType(Enum):
    """Tipos de mensagem STUN"""
    BINDING_REQUEST = 0x0001
    BINDING_RESPONSE = 0x0101
    BINDING_ERROR = 0x0111

class STUNAttribute(Enum):
    """Atributos STUN"""
    MAPPED_ADDRESS = 0x0001
    USERNAME = 0x0006
    MESSAGE_INTEGRITY = 0x0008
    ERROR_CODE = 0x0009
    UNKNOWN_ATTRIBUTES = 0x000A
    REALM = 0x0014
    NONCE = 0x0015
    XOR_MAPPED_ADDRESS = 0x0020
    SOFTWARE = 0x8022
    ALTERNATE_SERVER = 0x8023
    FINGERPRINT = 0x8028

@dataclass
class NATMapping:
    """Mapeamento NAT descoberto"""
    local_ip: str
    local_port: int
    external_ip: str
    external_port: int
    nat_type: str
    timestamp: float

@dataclass
class STUNServer:
    """Servidor STUN"""
    host: str
    port: int
    username: str = ""
    password: str = ""

class QuantumNATTraversal:
    """Sistema NAT Traversal para QuantumShield"""
    
    def __init__(self):
        # Servidores STUN gratuitos
        self.stun_servers = [
            STUNServer("stun.l.google.com", 19302),
            STUNServer("stun1.l.google.com", 19302),
            STUNServer("stun2.l.google.com", 19302),
            STUNServer("stun3.l.google.com", 19302),
            STUNServer("stun4.l.google.com", 19302),
            STUNServer("stun.cloudflare.com", 3478),
            STUNServer("stun.nextcloud.com", 3478),
            STUNServer("stun.sipgate.net", 3478),
            STUNServer("stun.voiparound.com", 3478),
            STUNServer("stun.voipbuster.com", 3478),
        ]
        
        # Cache de mapeamentos NAT
        self.nat_mappings = {}
        
        # Servidor TURN embarcado (peer-to-peer relay)
        self.turn_relays = {}
        self.relay_active = False
        
        # Estatísticas
        self.stats = {
            'stun_requests': 0,
            'stun_successes': 0,
            'nat_mappings_discovered': 0,
            'relay_connections': 0
        }
        
    def create_stun_message(self, msg_type: STUNMessageType, transaction_id: bytes = None) -> bytes:
        """Cria mensagem STUN"""
        if transaction_id is None:
            transaction_id = random.randbytes(12)
        
        # Header STUN: Type (2) + Length (2) + Magic Cookie (4) + Transaction ID (12)
        magic_cookie = 0x2112A442
        message_length = 0  # Será atualizado se houver atributos
        
        header = struct.pack('!HHI', msg_type.value, message_length, magic_cookie)
        header += transaction_id
        
        return header
    
    def parse_stun_response(self, data: bytes) -> Optional[Dict]:
        """Analisa resposta STUN"""
        if len(data) < 20:
            return None
        
        try:
            # Parse header
            msg_type, msg_length, magic_cookie = struct.unpack('!HHI', data[:8])
            transaction_id = data[8:20]
            
            if magic_cookie != 0x2112A442:
                return None
            
            # Parse atributos
            attributes = {}
            offset = 20
            
            while offset < len(data):
                if offset + 4 > len(data):
                    break
                
                attr_type, attr_length = struct.unpack('!HH', data[offset:offset+4])
                offset += 4
                
                if offset + attr_length > len(data):
                    break
                
                attr_data = data[offset:offset+attr_length]
                offset += attr_length
                
                # Padding para alinhamento de 4 bytes
                padding = (4 - (attr_length % 4)) % 4
                offset += padding
                
                attributes[attr_type] = attr_data
            
            return {
                'type': msg_type,
                'length': msg_length,
                'transaction_id': transaction_id,
                'attributes': attributes
            }
            
        except struct.error:
            return None
    
    def extract_mapped_address(self, attr_data: bytes, xor_mapped: bool = False) -> Optional[Tuple[str, int]]:
        """Extrai endereço mapeado do atributo STUN"""
        if len(attr_data) < 8:
            return None
        
        try:
            # Parse: Reserved (1) + Family (1) + Port (2) + Address (4)
            reserved, family, port = struct.unpack('!BBH', attr_data[:4])
            
            if family == 1:  # IPv4
                if len(attr_data) < 8:
                    return None
                
                ip_bytes = attr_data[4:8]
                
                if xor_mapped:
                    # XOR com magic cookie para XOR-MAPPED-ADDRESS
                    magic_cookie = 0x2112A442
                    port ^= (magic_cookie >> 16) & 0xFFFF
                    ip_int = struct.unpack('!I', ip_bytes)[0]
                    ip_int ^= magic_cookie
                    ip_bytes = struct.pack('!I', ip_int)
                
                ip = socket.inet_ntoa(ip_bytes)
                return (ip, port)
            
        except (struct.error, socket.error):
            pass
        
        return None
    
    def discover_nat_mapping(self, local_port: int, stun_server: STUNServer = None) -> Optional[NATMapping]:
        """Descobre mapeamento NAT usando STUN"""
        if stun_server is None:
            stun_server = random.choice(self.stun_servers)
        
        try:
            # Criar socket local
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', local_port))
            sock.settimeout(5.0)
            
            # Criar mensagem STUN Binding Request
            stun_request = self.create_stun_message(STUNMessageType.BINDING_REQUEST)
            
            # Enviar para servidor STUN
            sock.sendto(stun_request, (stun_server.host, stun_server.port))
            self.stats['stun_requests'] += 1
            
            # Aguardar resposta
            response_data, addr = sock.recvfrom(1024)
            
            # Parse resposta
            response = self.parse_stun_response(response_data)
            if not response:
                return None
            
            # Extrair endereço mapeado
            mapped_address = None
            
            # Tentar XOR-MAPPED-ADDRESS primeiro
            if STUNAttribute.XOR_MAPPED_ADDRESS.value in response['attributes']:
                mapped_address = self.extract_mapped_address(
                    response['attributes'][STUNAttribute.XOR_MAPPED_ADDRESS.value],
                    xor_mapped=True
                )
            
            # Fallback para MAPPED-ADDRESS
            if not mapped_address and STUNAttribute.MAPPED_ADDRESS.value in response['attributes']:
                mapped_address = self.extract_mapped_address(
                    response['attributes'][STUNAttribute.MAPPED_ADDRESS.value],
                    xor_mapped=False
                )
            
            if mapped_address:
                external_ip, external_port = mapped_address
                local_ip = sock.getsockname()[0]
                
                # Determinar tipo de NAT (simplificado)
                nat_type = "unknown"
                if local_ip == external_ip:
                    nat_type = "no_nat"
                elif local_port == external_port:
                    nat_type = "full_cone"
                else:
                    nat_type = "symmetric"
                
                mapping = NATMapping(
                    local_ip=local_ip,
                    local_port=local_port,
                    external_ip=external_ip,
                    external_port=external_port,
                    nat_type=nat_type,
                    timestamp=time.time()
                )
                
                # Cache do mapeamento
                self.nat_mappings[local_port] = mapping
                self.stats['stun_successes'] += 1
                self.stats['nat_mappings_discovered'] += 1
                
                logger.info(f"NAT mapping descoberto: {local_ip}:{local_port} -> {external_ip}:{external_port} ({nat_type})")
                
                sock.close()
                return mapping
            
            sock.close()
            
        except socket.timeout:
            logger.warning(f"Timeout STUN com {stun_server.host}:{stun_server.port}")
        except Exception as e:
            logger.error(f"Erro STUN: {e}")
        
        return None
    
    def discover_multiple_mappings(self, ports: List[int]) -> Dict[int, NATMapping]:
        """Descobre múltiplos mapeamentos NAT"""
        mappings = {}
        
        for port in ports:
            # Tentar com diferentes servidores STUN
            for stun_server in self.stun_servers[:3]:  # Tentar 3 servidores
                mapping = self.discover_nat_mapping(port, stun_server)
                if mapping:
                    mappings[port] = mapping
                    break
                time.sleep(0.5)  # Pequena pausa entre tentativas
        
        return mappings
    
    def create_hole_punch(self, local_port: int, target_ip: str, target_port: int) -> bool:
        """Cria hole punch para conectividade direta"""
        try:
            # Descobrir mapeamento NAT local
            mapping = self.nat_mappings.get(local_port)
            if not mapping:
                mapping = self.discover_nat_mapping(local_port)
                if not mapping:
                    return False
            
            # Criar socket para hole punching
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', local_port))
            sock.settimeout(2.0)
            
            # Enviar pacotes para criar hole
            hole_punch_data = b"QUANTUM_HOLE_PUNCH"
            
            for i in range(5):  # Múltiplas tentativas
                sock.sendto(hole_punch_data, (target_ip, target_port))
                time.sleep(0.1)
            
            # Tentar receber resposta
            try:
                response, addr = sock.recvfrom(1024)
                if response == b"QUANTUM_HOLE_PUNCH_ACK":
                    logger.info(f"Hole punch bem-sucedido: {target_ip}:{target_port}")
                    sock.close()
                    return True
            except socket.timeout:
                pass
            
            sock.close()
            
        except Exception as e:
            logger.error(f"Erro no hole punch: {e}")
        
        return False
    
    def start_relay_server(self, port: int = 3478):
        """Inicia servidor TURN embarcado (relay)"""
        try:
            self.relay_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.relay_socket.bind(('0.0.0.0', port))
            self.relay_active = True
            
            logger.info(f"Servidor TURN relay iniciado na porta {port}")
            
            while self.relay_active:
                try:
                    data, addr = self.relay_socket.recvfrom(4096)
                    
                    # Processar mensagem TURN em thread separada
                    threading.Thread(
                        target=self.handle_relay_message,
                        args=(data, addr),
                        daemon=True
                    ).start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.relay_active:
                        logger.error(f"Erro no servidor relay: {e}")
            
        except Exception as e:
            logger.error(f"Erro ao iniciar servidor relay: {e}")
        finally:
            if hasattr(self, 'relay_socket'):
                self.relay_socket.close()
    
    def handle_relay_message(self, data: bytes, addr: Tuple[str, int]):
        """Processa mensagem do relay TURN"""
        try:
            # Implementação simplificada de relay
            # Em produção, implementar protocolo TURN completo
            
            if data.startswith(b"RELAY_REQUEST:"):
                # Extrair endereço de destino
                request_data = data[14:].decode('utf-8')
                target_ip, target_port = request_data.split(':')
                target_port = int(target_port)
                
                # Criar sessão de relay
                session_id = hashlib.md5(f"{addr[0]}:{addr[1]}:{target_ip}:{target_port}".encode()).hexdigest()[:16]
                
                self.turn_relays[session_id] = {
                    'client1': addr,
                    'client2': (target_ip, target_port),
                    'created': time.time()
                }
                
                # Responder com ID da sessão
                response = f"RELAY_SESSION:{session_id}".encode('utf-8')
                self.relay_socket.sendto(response, addr)
                
                self.stats['relay_connections'] += 1
                logger.info(f"Sessão relay criada: {session_id}")
            
            elif data.startswith(b"RELAY_DATA:"):
                # Relay de dados
                parts = data[11:].split(b':', 1)
                if len(parts) == 2:
                    session_id = parts[0].decode('utf-8')
                    relay_data = parts[1]
                    
                    if session_id in self.turn_relays:
                        session = self.turn_relays[session_id]
                        
                        # Determinar destinatário
                        if addr == session['client1']:
                            target = session['client2']
                        elif addr == session['client2']:
                            target = session['client1']
                        else:
                            return
                        
                        # Relay dados
                        self.relay_socket.sendto(relay_data, target)
            
        except Exception as e:
            logger.error(f"Erro ao processar mensagem relay: {e}")
    
    def connect_via_relay(self, relay_ip: str, relay_port: int, target_ip: str, target_port: int) -> Optional[str]:
        """Conecta via servidor TURN relay"""
        try:
            # Criar socket para relay
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            
            # Solicitar sessão relay
            request = f"RELAY_REQUEST:{target_ip}:{target_port}".encode('utf-8')
            sock.sendto(request, (relay_ip, relay_port))
            
            # Aguardar resposta
            response, addr = sock.recvfrom(1024)
            
            if response.startswith(b"RELAY_SESSION:"):
                session_id = response[14:].decode('utf-8')
                logger.info(f"Conectado via relay: {session_id}")
                return session_id
            
        except Exception as e:
            logger.error(f"Erro ao conectar via relay: {e}")
        
        return None
    
    def send_via_relay(self, sock: socket.socket, relay_addr: Tuple[str, int], session_id: str, data: bytes):
        """Envia dados via relay TURN"""
        relay_message = f"RELAY_DATA:{session_id}:".encode('utf-8') + data
        sock.sendto(relay_message, relay_addr)
    
    def establish_p2p_connection(self, local_port: int, peer_info: Dict) -> Optional[socket.socket]:
        """Estabelece conexão P2P com outro peer"""
        peer_ip = peer_info['ip']
        peer_port = peer_info['port']
        
        # Método 1: Tentativa direta
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', local_port))
            sock.settimeout(2.0)
            
            # Teste de conectividade direta
            test_data = b"QUANTUM_P2P_TEST"
            sock.sendto(test_data, (peer_ip, peer_port))
            
            response, addr = sock.recvfrom(1024)
            if response == b"QUANTUM_P2P_ACK":
                logger.info(f"Conexão P2P direta estabelecida: {peer_ip}:{peer_port}")
                return sock
            
        except (socket.timeout, socket.error):
            pass
        
        # Método 2: Hole punching
        if self.create_hole_punch(local_port, peer_ip, peer_port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(('0.0.0.0', local_port))
                sock.connect((peer_ip, peer_port))
                logger.info(f"Conexão P2P via hole punch: {peer_ip}:{peer_port}")
                return sock
            except socket.error:
                pass
        
        # Método 3: Relay TURN
        for relay_info in peer_info.get('relays', []):
            session_id = self.connect_via_relay(
                relay_info['ip'], relay_info['port'],
                peer_ip, peer_port
            )
            if session_id:
                # Retornar socket configurado para relay
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(('0.0.0.0', local_port))
                # Adicionar metadados do relay ao socket
                sock._relay_info = {
                    'session_id': session_id,
                    'relay_addr': (relay_info['ip'], relay_info['port'])
                }
                logger.info(f"Conexão P2P via relay: {session_id}")
                return sock
        
        logger.warning(f"Falha ao estabelecer conexão P2P com {peer_ip}:{peer_port}")
        return None
    
    def get_connectivity_info(self, local_port: int) -> Dict:
        """Obtém informações de conectividade para compartilhar com peers"""
        # Descobrir mapeamento NAT
        mapping = self.nat_mappings.get(local_port)
        if not mapping:
            mapping = self.discover_nat_mapping(local_port)
        
        info = {
            'local_port': local_port,
            'timestamp': time.time()
        }
        
        if mapping:
            info.update({
                'external_ip': mapping.external_ip,
                'external_port': mapping.external_port,
                'nat_type': mapping.nat_type
            })
        
        # Adicionar informações de relay disponíveis
        info['relays'] = []
        if self.relay_active:
            info['relays'].append({
                'ip': mapping.external_ip if mapping else '127.0.0.1',
                'port': 3478,
                'type': 'embedded'
            })
        
        return info
    
    def get_stats(self) -> Dict:
        """Obtém estatísticas do NAT traversal"""
        return {
            'stun_requests': self.stats['stun_requests'],
            'stun_successes': self.stats['stun_successes'],
            'success_rate': (self.stats['stun_successes'] / max(1, self.stats['stun_requests'])) * 100,
            'nat_mappings_discovered': self.stats['nat_mappings_discovered'],
            'relay_connections': self.stats['relay_connections'],
            'relay_active': self.relay_active,
            'cached_mappings': len(self.nat_mappings)
        }

def test_nat_traversal():
    """Teste do sistema NAT Traversal"""
    print("🛡️ Testando QuantumNATTraversal...")
    
    nat_system = QuantumNATTraversal()
    
    try:
        # Teste 1: Descoberta de mapeamento NAT
        print("\n🔍 Descobrindo mapeamento NAT...")
        mapping = nat_system.discover_nat_mapping(12345)
        
        if mapping:
            print(f"✅ Mapeamento descoberto:")
            print(f"  Local: {mapping.local_ip}:{mapping.local_port}")
            print(f"  Externo: {mapping.external_ip}:{mapping.external_port}")
            print(f"  Tipo NAT: {mapping.nat_type}")
        else:
            print("❌ Falha ao descobrir mapeamento NAT")
        
        # Teste 2: Múltiplos mapeamentos
        print("\n🔍 Descobrindo múltiplos mapeamentos...")
        ports = [12346, 12347, 12348]
        mappings = nat_system.discover_multiple_mappings(ports)
        
        print(f"✅ {len(mappings)} mapeamentos descobertos")
        for port, mapping in mappings.items():
            print(f"  Porta {port}: {mapping.external_ip}:{mapping.external_port}")
        
        # Teste 3: Informações de conectividade
        print("\n📋 Obtendo informações de conectividade...")
        connectivity_info = nat_system.get_connectivity_info(12345)
        print(f"✅ Info de conectividade: {connectivity_info}")
        
        # Teste 4: Estatísticas
        print("\n📊 Estatísticas:")
        stats = nat_system.get_stats()
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        print("\n✅ Teste NAT Traversal concluído com sucesso!")
        return True
        
    except Exception as e:
        print(f"\n❌ Erro no teste: {e}")
        return False

if __name__ == "__main__":
    test_nat_traversal()

