#!/usr/bin/env python3
"""
🛡️ QuantumShield - P2P Network Integration
Arquivo: quantum_p2p_integration.py
Descrição: Integração completa do sistema P2P mesh com DHT, NAT Traversal e VPN
Autor: QuantumShield Team
Versão: 2.0
Data: 03/07/2025
"""

import threading
import time
import logging
import json
import socket
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import secrets

# Importar módulos QuantumShield P2P
from quantum_dht import QuantumDHT, DHTNode
from quantum_nat_traversal import QuantumNATTraversal, NATMapping
from quantum_p2p_vpn import QuantumP2PVPN, VPNPeer

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class P2PConnection:
    """Conexão P2P estabelecida"""
    peer_id: str
    connection_type: str  # direct, hole_punch, relay, vpn
    local_port: int
    remote_ip: str
    remote_port: int
    established_at: float
    last_activity: float
    bytes_sent: int = 0
    bytes_received: int = 0

@dataclass
class P2PService:
    """Serviço P2P anunciado"""
    service_type: str
    service_data: Dict
    port: int
    announced_at: float

class QuantumP2PNetwork:
    """Sistema P2P mesh completo QuantumShield"""
    
    def __init__(self, config: Dict = None):
        self.config = config or self.get_default_config()
        
        # Componentes P2P
        self.dht = QuantumDHT(port=self.config['dht_port'])
        self.nat_traversal = QuantumNATTraversal()
        
        # Inicializar VPN apenas se habilitada
        self.vpn = None
        if self.config.get('enable_vpn', True):
            self.vpn = QuantumP2PVPN(
                vpn_network=self.config.get('vpn_network', '10.42.0.0/24'),
                local_vpn_ip=self.config.get('local_vpn_ip')
            )
        
        # Estado da rede
        self.running = False
        self.node_id = self.dht.node_id
        self.local_ip = self.dht.local_ip
        
        # Conexões ativas
        self.connections = {}  # peer_id -> P2PConnection
        self.services = {}     # service_type -> P2PService
        
        # Configurações de rede
        self.base_port = self.config['base_port']
        self.port_range = self.config['port_range']
        self.available_ports = list(range(self.base_port, self.base_port + self.port_range))
        
        # Threads de manutenção
        self.maintenance_thread = None
        self.discovery_thread = None
        
        # Callbacks
        self.callbacks = {
            'peer_connected': [],
            'peer_disconnected': [],
            'service_discovered': [],
            'message_received': []
        }
        
        # Estatísticas
        self.stats = {
            'network_start_time': 0,
            'peers_discovered': 0,
            'connections_established': 0,
            'services_announced': 0,
            'messages_sent': 0,
            'messages_received': 0,
            'nat_mappings_created': 0,
            'vpn_active': False
        }
        
    def get_default_config(self) -> Dict:
        """Configuração padrão da rede P2P"""
        return {
            'dht_port': 8888,
            'base_port': 9000,
            'port_range': 100,
            'vpn_network': '10.42.0.0/24',
            'local_vpn_ip': None,
            'enable_vpn': True,
            'enable_nat_traversal': True,
            'discovery_interval': 30,
            'maintenance_interval': 60,
            'connection_timeout': 300,
            'max_connections': 50
        }
    
    def register_callback(self, event_type: str, callback):
        """Registra callback para eventos da rede"""
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
    
    def emit_event(self, event_type: str, data: Any):
        """Emite evento para callbacks registrados"""
        for callback in self.callbacks.get(event_type, []):
            try:
                callback(data)
            except Exception as e:
                logger.error(f"Erro no callback {event_type}: {e}")
    
    def start_network(self) -> bool:
        """Inicia rede P2P completa"""
        try:
            logger.info("🚀 Iniciando rede P2P QuantumShield...")
            
            self.running = True
            self.stats['network_start_time'] = time.time()
            
            # 1. Iniciar DHT
            logger.info("📡 Iniciando DHT...")
            self.dht.start()
            time.sleep(2)  # Aguardar bootstrap
            
            # 2. Descobrir mapeamentos NAT
            if self.config['enable_nat_traversal']:
                logger.info("🔍 Descobrindo mapeamentos NAT...")
                self.discover_nat_mappings()
            
            # 3. Iniciar VPN (se habilitada)
            if self.config['enable_vpn'] and self.vpn:
                logger.info("🛡️ Iniciando VPN P2P...")
                if self.vpn.start():
                    self.stats['vpn_active'] = True
                    logger.info("✅ VPN P2P ativa")
                else:
                    logger.warning("⚠️ VPN P2P não pôde ser iniciada")
            
            # 4. Iniciar threads de manutenção
            self.start_maintenance_threads()
            
            # 5. Anunciar presença na rede
            self.announce_presence()
            
            logger.info(f"✅ Rede P2P iniciada - Node ID: {self.node_id[:16]}...")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao iniciar rede P2P: {e}")
            return False
    
    def discover_nat_mappings(self):
        """Descobre mapeamentos NAT para portas necessárias"""
        try:
            # Descobrir mapeamentos para portas principais
            ports_to_map = [
                self.config['dht_port'],
                self.base_port,
                self.base_port + 1,
                self.base_port + 2
            ]
            
            mappings = self.nat_traversal.discover_multiple_mappings(ports_to_map)
            self.stats['nat_mappings_created'] = len(mappings)
            
            logger.info(f"🔍 {len(mappings)} mapeamentos NAT descobertos")
            
        except Exception as e:
            logger.error(f"Erro ao descobrir NAT: {e}")
    
    def start_maintenance_threads(self):
        """Inicia threads de manutenção"""
        # Thread de descoberta de peers
        self.discovery_thread = threading.Thread(
            target=self.peer_discovery_loop,
            daemon=True
        )
        self.discovery_thread.start()
        
        # Thread de manutenção geral
        self.maintenance_thread = threading.Thread(
            target=self.maintenance_loop,
            daemon=True
        )
        self.maintenance_thread.start()
    
    def announce_presence(self):
        """Anuncia presença na rede DHT"""
        try:
            # Obter informações de conectividade
            connectivity_info = self.nat_traversal.get_connectivity_info(self.base_port)
            
            # Dados do nó
            node_data = {
                'node_id': self.node_id,
                'local_ip': self.local_ip,
                'dht_port': self.config['dht_port'],
                'base_port': self.base_port,
                'capabilities': ['dht', 'nat_traversal', 'vpn', 'blockchain', 'chat'],
                'connectivity': connectivity_info,
                'timestamp': time.time()
            }
            
            if self.stats['vpn_active']:
                node_data['vpn_ip'] = self.vpn.local_vpn_ip if self.vpn else None
            
            # Anunciar na DHT
            self.dht.announce_service('quantumshield_node', node_data)
            
            logger.info("📢 Presença anunciada na rede")
            
        except Exception as e:
            logger.error(f"Erro ao anunciar presença: {e}")
    
    def peer_discovery_loop(self):
        """Loop de descoberta de peers"""
        while self.running:
            try:
                # Buscar nós QuantumShield na DHT
                nodes = self.dht.find_services('quantumshield_node')
                
                for node_data in nodes:
                    peer_id = node_data.get('node_id')
                    
                    if peer_id and peer_id != self.node_id:
                        if peer_id not in self.connections:
                            # Tentar conectar ao peer
                            self.attempt_peer_connection(node_data)
                
                self.stats['peers_discovered'] = len(nodes)
                
                time.sleep(self.config['discovery_interval'])
                
            except Exception as e:
                logger.error(f"Erro na descoberta de peers: {e}")
                time.sleep(30)
    
    def attempt_peer_connection(self, peer_data: Dict):
        """Tenta conectar a um peer"""
        try:
            peer_id = peer_data['node_id']
            
            logger.info(f"🔗 Tentando conectar ao peer: {peer_id[:16]}...")
            
            # Obter informações de conectividade do peer
            connectivity = peer_data.get('connectivity', {})
            peer_ip = connectivity.get('external_ip', peer_data.get('local_ip'))
            peer_port = connectivity.get('external_port', peer_data.get('base_port'))
            
            if not peer_ip or not peer_port:
                logger.warning(f"Informações de conectividade insuficientes para {peer_id[:16]}")
                return
            
            # Tentar estabelecer conexão P2P
            connection = self.establish_p2p_connection(peer_id, peer_ip, peer_port, peer_data)
            
            if connection:
                self.connections[peer_id] = connection
                self.stats['connections_established'] += 1
                
                # Emitir evento
                self.emit_event('peer_connected', {
                    'peer_id': peer_id,
                    'connection': connection
                })
                
                logger.info(f"✅ Conectado ao peer: {peer_id[:16]} via {connection.connection_type}")
                
                # Se VPN ativa, adicionar peer à VPN
                if self.stats['vpn_active'] and 'vpn_ip' in peer_data:
                    self.add_peer_to_vpn(peer_id, peer_data)
            
        except Exception as e:
            logger.error(f"Erro ao conectar ao peer: {e}")
    
    def establish_p2p_connection(self, peer_id: str, peer_ip: str, peer_port: int, peer_data: Dict) -> Optional[P2PConnection]:
        """Estabelece conexão P2P com peer"""
        try:
            local_port = self.get_available_port()
            if not local_port:
                return None
            
            # Método 1: Conexão direta
            if self.test_direct_connection(peer_ip, peer_port):
                return P2PConnection(
                    peer_id=peer_id,
                    connection_type='direct',
                    local_port=local_port,
                    remote_ip=peer_ip,
                    remote_port=peer_port,
                    established_at=time.time(),
                    last_activity=time.time()
                )
            
            # Método 2: Hole punching
            if self.nat_traversal.create_hole_punch(local_port, peer_ip, peer_port):
                return P2PConnection(
                    peer_id=peer_id,
                    connection_type='hole_punch',
                    local_port=local_port,
                    remote_ip=peer_ip,
                    remote_port=peer_port,
                    established_at=time.time(),
                    last_activity=time.time()
                )
            
            # Método 3: Relay TURN
            connectivity = peer_data.get('connectivity', {})
            relays = connectivity.get('relays', [])
            
            for relay in relays:
                session_id = self.nat_traversal.connect_via_relay(
                    relay['ip'], relay['port'], peer_ip, peer_port
                )
                if session_id:
                    return P2PConnection(
                        peer_id=peer_id,
                        connection_type='relay',
                        local_port=local_port,
                        remote_ip=relay['ip'],
                        remote_port=relay['port'],
                        established_at=time.time(),
                        last_activity=time.time()
                    )
            
            return None
            
        except Exception as e:
            logger.error(f"Erro ao estabelecer conexão P2P: {e}")
            return None
    
    def test_direct_connection(self, ip: str, port: int) -> bool:
        """Testa conectividade direta com peer"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            
            test_data = b"QUANTUM_P2P_TEST"
            sock.sendto(test_data, (ip, port))
            
            response, addr = sock.recvfrom(1024)
            sock.close()
            
            return response == b"QUANTUM_P2P_ACK"
            
        except (socket.timeout, socket.error):
            return False
    
    def add_peer_to_vpn(self, peer_id: str, peer_data: Dict):
        """Adiciona peer à VPN"""
        try:
            if not self.vpn or 'vpn_ip' not in peer_data:
                return
            
            # Gerar chave pública simulada (em produção, usar troca de chaves real)
            peer_public_key = hashlib.sha256(peer_id.encode()).digest()
            
            connectivity = peer_data.get('connectivity', {})
            external_ip = connectivity.get('external_ip', peer_data.get('local_ip'))
            external_port = connectivity.get('external_port', peer_data.get('base_port'))
            
            self.vpn.add_peer(
                peer_id=peer_id,
                peer_public_key=peer_public_key,
                external_ip=external_ip,
                external_port=external_port + 1,  # Porta VPN
                vpn_ip=peer_data['vpn_ip']
            )
            
            logger.info(f"🛡️ Peer adicionado à VPN: {peer_id[:16]} ({peer_data['vpn_ip']})")
            
        except Exception as e:
            logger.error(f"Erro ao adicionar peer à VPN: {e}")
    
    def get_available_port(self) -> Optional[int]:
        """Obtém porta disponível"""
        if self.available_ports:
            return self.available_ports.pop(0)
        return None
    
    def maintenance_loop(self):
        """Loop de manutenção da rede"""
        while self.running:
            try:
                current_time = time.time()
                
                # Verificar conexões inativas
                inactive_peers = []
                for peer_id, connection in self.connections.items():
                    if current_time - connection.last_activity > self.config['connection_timeout']:
                        inactive_peers.append(peer_id)
                
                # Remover conexões inativas
                for peer_id in inactive_peers:
                    self.disconnect_peer(peer_id)
                
                # Re-anunciar presença periodicamente
                if int(current_time) % 300 == 0:  # A cada 5 minutos
                    self.announce_presence()
                
                # Limitar número de conexões
                if len(self.connections) > self.config['max_connections']:
                    # Remover conexões mais antigas
                    oldest_peers = sorted(
                        self.connections.items(),
                        key=lambda x: x[1].last_activity
                    )
                    
                    for peer_id, _ in oldest_peers[:len(self.connections) - self.config['max_connections']]:
                        self.disconnect_peer(peer_id)
                
                time.sleep(self.config['maintenance_interval'])
                
            except Exception as e:
                logger.error(f"Erro na manutenção: {e}")
                time.sleep(60)
    
    def disconnect_peer(self, peer_id: str):
        """Desconecta peer"""
        try:
            if peer_id in self.connections:
                connection = self.connections[peer_id]
                
                # Liberar porta
                self.available_ports.append(connection.local_port)
                
                # Remover da lista de conexões
                del self.connections[peer_id]
                
                # Emitir evento
                self.emit_event('peer_disconnected', {
                    'peer_id': peer_id,
                    'connection': connection
                })
                
                logger.info(f"🔌 Peer desconectado: {peer_id[:16]}")
            
        except Exception as e:
            logger.error(f"Erro ao desconectar peer: {e}")
    
    def announce_service(self, service_type: str, service_data: Dict, port: int = None):
        """Anuncia serviço na rede"""
        try:
            if port is None:
                port = self.get_available_port()
                if not port:
                    logger.error("Nenhuma porta disponível para serviço")
                    return False
            
            # Criar serviço
            service = P2PService(
                service_type=service_type,
                service_data=service_data,
                port=port,
                announced_at=time.time()
            )
            
            self.services[service_type] = service
            
            # Anunciar na DHT
            announcement_data = {
                'node_id': self.node_id,
                'service_type': service_type,
                'service_data': service_data,
                'port': port,
                'timestamp': time.time()
            }
            
            self.dht.announce_service(f"service_{service_type}", announcement_data)
            
            self.stats['services_announced'] += 1
            logger.info(f"📢 Serviço anunciado: {service_type} (porta {port})")
            
            return True
            
        except Exception as e:
            logger.error(f"Erro ao anunciar serviço: {e}")
            return False
    
    def discover_services(self, service_type: str) -> List[Dict]:
        """Descobre serviços na rede"""
        try:
            services = self.dht.find_services(f"service_{service_type}")
            
            # Filtrar serviços próprios
            filtered_services = []
            for service in services:
                if service.get('node_id') != self.node_id:
                    filtered_services.append(service)
            
            return filtered_services
            
        except Exception as e:
            logger.error(f"Erro ao descobrir serviços: {e}")
            return []
    
    def send_message(self, peer_id: str, message_type: str, data: Dict) -> bool:
        """Envia mensagem para peer"""
        try:
            if peer_id not in self.connections:
                logger.warning(f"Peer não conectado: {peer_id[:16]}")
                return False
            
            connection = self.connections[peer_id]
            
            # Criar mensagem
            message = {
                'type': message_type,
                'from': self.node_id,
                'to': peer_id,
                'data': data,
                'timestamp': time.time()
            }
            
            message_data = json.dumps(message).encode('utf-8')
            
            # Enviar via socket UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message_data, (connection.remote_ip, connection.remote_port))
            sock.close()
            
            # Atualizar estatísticas
            connection.bytes_sent += len(message_data)
            connection.last_activity = time.time()
            self.stats['messages_sent'] += 1
            
            return True
            
        except Exception as e:
            logger.error(f"Erro ao enviar mensagem: {e}")
            return False
    
    def broadcast_message(self, message_type: str, data: Dict):
        """Envia mensagem para todos os peers"""
        for peer_id in self.connections:
            self.send_message(peer_id, message_type, data)
    
    def stop_network(self):
        """Para rede P2P"""
        try:
            logger.info("🛑 Parando rede P2P...")
            
            self.running = False
            
            # Parar VPN
            if self.stats['vpn_active'] and self.vpn:
                self.vpn.stop()
            
            # Parar DHT
            self.dht.stop()
            
            # Desconectar todos os peers
            for peer_id in list(self.connections.keys()):
                self.disconnect_peer(peer_id)
            
            logger.info("✅ Rede P2P parada")
            
        except Exception as e:
            logger.error(f"Erro ao parar rede: {e}")
    
    def get_network_stats(self) -> Dict:
        """Obtém estatísticas da rede"""
        uptime = time.time() - self.stats['network_start_time'] if self.stats['network_start_time'] else 0
        
        # Combinar estatísticas de todos os componentes
        dht_stats = self.dht.get_stats()
        nat_stats = self.nat_traversal.get_stats()
        vpn_stats = self.vpn.get_stats() if self.vpn and self.stats['vpn_active'] else {}
        
        return {
            'network_uptime': int(uptime),
            'node_id': self.node_id[:16] + "...",
            'local_ip': self.local_ip,
            'running': self.running,
            'connections_active': len(self.connections),
            'services_announced': len(self.services),
            'dht': dht_stats,
            'nat_traversal': nat_stats,
            'vpn': vpn_stats,
            'general': self.stats
        }
    
    def get_peer_list(self) -> List[Dict]:
        """Obtém lista de peers conectados"""
        peer_list = []
        
        for peer_id, connection in self.connections.items():
            peer_info = {
                'peer_id': peer_id[:16] + "...",
                'connection_type': connection.connection_type,
                'remote_ip': connection.remote_ip,
                'remote_port': connection.remote_port,
                'connected_since': connection.established_at,
                'last_activity': connection.last_activity,
                'bytes_sent': connection.bytes_sent,
                'bytes_received': connection.bytes_received
            }
            peer_list.append(peer_info)
        
        return peer_list

def test_p2p_integration():
    """Teste da integração P2P completa"""
    print("🛡️ Testando Integração P2P QuantumShield...")
    
    # Configuração de teste
    config = {
        'dht_port': 8890,
        'base_port': 9100,
        'port_range': 10,
        'enable_vpn': False,  # Desabilitar VPN para teste
        'enable_nat_traversal': True,
        'discovery_interval': 5,
        'maintenance_interval': 10
    }
    
    network = QuantumP2PNetwork(config)
    
    try:
        # Registrar callbacks de teste
        def on_peer_connected(data):
            print(f"✅ Peer conectado: {data['peer_id'][:16]}...")
        
        def on_peer_disconnected(data):
            print(f"🔌 Peer desconectado: {data['peer_id'][:16]}...")
        
        network.register_callback('peer_connected', on_peer_connected)
        network.register_callback('peer_disconnected', on_peer_disconnected)
        
        # Iniciar rede
        print("\n🚀 Iniciando rede P2P...")
        if network.start_network():
            print("✅ Rede P2P iniciada")
            
            # Aguardar um pouco para descoberta
            time.sleep(5)
            
            # Anunciar serviço de teste
            print("\n📢 Anunciando serviço...")
            network.announce_service('test_service', {
                'description': 'Serviço de teste QuantumShield',
                'version': '2.0'
            })
            
            # Descobrir serviços
            print("\n🔍 Descobrindo serviços...")
            services = network.discover_services('test_service')
            print(f"✅ {len(services)} serviços descobertos")
            
            # Aguardar mais um pouco
            time.sleep(3)
            
            # Verificar estatísticas
            print("\n📊 Estatísticas da rede:")
            stats = network.get_network_stats()
            
            print(f"  Node ID: {stats['node_id']}")
            print(f"  Uptime: {stats['network_uptime']}s")
            print(f"  Conexões ativas: {stats['connections_active']}")
            print(f"  Serviços anunciados: {stats['services_announced']}")
            print(f"  DHT - Nós descobertos: {stats['dht']['nodes_discovered']}")
            print(f"  NAT - Taxa de sucesso: {stats['nat_traversal']['success_rate']:.1f}%")
            
            # Listar peers
            peers = network.get_peer_list()
            print(f"\n👥 Peers conectados: {len(peers)}")
            for peer in peers:
                print(f"  {peer['peer_id']} via {peer['connection_type']}")
            
            # Parar rede
            network.stop_network()
            print("\n✅ Teste de integração P2P concluído")
            
            return True
            
        else:
            print("❌ Falha ao iniciar rede P2P")
            return False
            
    except Exception as e:
        print(f"❌ Erro no teste: {e}")
        return False

if __name__ == "__main__":
    test_p2p_integration()

