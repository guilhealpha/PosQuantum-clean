#!/usr/bin/env python3
"""
🛡️ QuantumShield - P2P VPN System
Arquivo: quantum_p2p_vpn.py
Descrição: Sistema VPN P2P mesh com interface TUN/TAP
Autor: QuantumShield Team
Versão: 2.0
Data: 03/07/2025
"""

import os
import sys
import socket
import struct
import threading
import time
import logging
import subprocess
import ipaddress
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from pathlib import Path
import json
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class VPNPeer:
    """Peer da VPN"""
    peer_id: str
    public_key: bytes
    vpn_ip: str
    external_ip: str
    external_port: int
    last_seen: float
    routes: List[str] = None
    
    def __post_init__(self):
        if self.routes is None:
            self.routes = []

@dataclass
class VPNPacket:
    """Pacote VPN encapsulado"""
    peer_id: str
    sequence: int
    timestamp: float
    encrypted_data: bytes
    hmac_tag: bytes

class TUNInterface:
    """Interface TUN para VPN"""
    
    def __init__(self, interface_name: str = "quantumvpn0", vpn_ip: str = "10.42.0.1", netmask: str = "255.255.255.0"):
        self.interface_name = interface_name
        self.vpn_ip = vpn_ip
        self.netmask = netmask
        self.tun_fd = None
        self.running = False
        
    def create_tun_interface(self) -> bool:
        """Cria interface TUN"""
        try:
            # No Linux, usar /dev/net/tun
            if sys.platform.startswith('linux'):
                return self._create_linux_tun()
            elif sys.platform == 'win32':
                return self._create_windows_tun()
            elif sys.platform == 'darwin':
                return self._create_macos_tun()
            else:
                logger.error(f"Plataforma não suportada: {sys.platform}")
                return False
                
        except Exception as e:
            logger.error(f"Erro ao criar interface TUN: {e}")
            return False
    
    def _create_linux_tun(self) -> bool:
        """Cria interface TUN no Linux"""
        try:
            import fcntl
            
            # Constantes para ioctl
            TUNSETIFF = 0x400454ca
            IFF_TUN = 0x0001
            IFF_NO_PI = 0x1000
            
            # Abrir /dev/net/tun
            self.tun_fd = os.open('/dev/net/tun', os.O_RDWR)
            
            # Configurar interface
            ifr = struct.pack('16sH', self.interface_name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
            fcntl.ioctl(self.tun_fd, TUNSETIFF, ifr)
            
            # Configurar IP da interface
            self._configure_interface_linux()
            
            logger.info(f"Interface TUN criada: {self.interface_name} ({self.vpn_ip})")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao criar TUN Linux: {e}")
            if self.tun_fd:
                os.close(self.tun_fd)
                self.tun_fd = None
            return False
    
    def _configure_interface_linux(self):
        """Configura interface TUN no Linux"""
        try:
            # Configurar IP
            subprocess.run([
                'ip', 'addr', 'add', f"{self.vpn_ip}/24", 
                'dev', self.interface_name
            ], check=True, capture_output=True)
            
            # Ativar interface
            subprocess.run([
                'ip', 'link', 'set', 'dev', self.interface_name, 'up'
            ], check=True, capture_output=True)
            
            logger.info(f"Interface {self.interface_name} configurada com IP {self.vpn_ip}")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Erro ao configurar interface: {e}")
            # Tentar método alternativo com ifconfig
            try:
                subprocess.run([
                    'ifconfig', self.interface_name, self.vpn_ip, 
                    'netmask', self.netmask, 'up'
                ], check=True, capture_output=True)
                logger.info(f"Interface configurada com ifconfig")
            except subprocess.CalledProcessError:
                logger.error("Falha ao configurar interface com ifconfig também")
    
    def _create_windows_tun(self) -> bool:
        """Cria interface TUN no Windows (usando TAP-Windows)"""
        try:
            # Implementação simplificada para Windows
            # Em produção, usar TAP-Windows adapter
            logger.warning("Interface TUN no Windows requer TAP-Windows adapter")
            
            # Simular interface para teste
            self.tun_fd = -1  # Placeholder
            logger.info(f"Interface TUN simulada no Windows: {self.interface_name}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao criar TUN Windows: {e}")
            return False
    
    def _create_macos_tun(self) -> bool:
        """Cria interface TUN no macOS"""
        try:
            # No macOS, usar utun
            self.tun_fd = os.open('/dev/tun0', os.O_RDWR)
            
            # Configurar interface
            subprocess.run([
                'ifconfig', 'utun0', self.vpn_ip, self.vpn_ip, 'up'
            ], check=True, capture_output=True)
            
            logger.info(f"Interface TUN criada no macOS: utun0 ({self.vpn_ip})")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao criar TUN macOS: {e}")
            return False
    
    def read_packet(self) -> Optional[bytes]:
        """Lê pacote da interface TUN"""
        if not self.tun_fd or self.tun_fd == -1:
            return None
        
        try:
            if sys.platform.startswith('linux'):
                # No Linux, ler diretamente
                packet = os.read(self.tun_fd, 4096)
                return packet
            else:
                # Outras plataformas podem precisar de tratamento especial
                return None
                
        except OSError as e:
            if e.errno != 11:  # EAGAIN
                logger.error(f"Erro ao ler pacote TUN: {e}")
            return None
    
    def write_packet(self, packet: bytes) -> bool:
        """Escreve pacote na interface TUN"""
        if not self.tun_fd or self.tun_fd == -1:
            return False
        
        try:
            if sys.platform.startswith('linux'):
                os.write(self.tun_fd, packet)
                return True
            else:
                # Outras plataformas
                return True
                
        except OSError as e:
            logger.error(f"Erro ao escrever pacote TUN: {e}")
            return False
    
    def close(self):
        """Fecha interface TUN"""
        if self.tun_fd and self.tun_fd != -1:
            try:
                os.close(self.tun_fd)
                logger.info(f"Interface TUN fechada: {self.interface_name}")
            except OSError:
                pass
            self.tun_fd = None

class QuantumP2PVPN:
    """Sistema VPN P2P QuantumShield"""
    
    def __init__(self, vpn_network: str = "10.42.0.0/24", local_vpn_ip: str = None):
        self.vpn_network = ipaddress.IPv4Network(vpn_network)
        self.local_vpn_ip = local_vpn_ip or str(list(self.vpn_network.hosts())[0])
        
        # Interface TUN
        self.tun_interface = TUNInterface(vpn_ip=self.local_vpn_ip)
        
        # Peers conectados
        self.peers = {}  # peer_id -> VPNPeer
        self.peer_sockets = {}  # peer_id -> socket
        
        # Criptografia
        self.local_private_key = secrets.token_bytes(32)
        self.local_public_key = self._derive_public_key(self.local_private_key)
        self.peer_keys = {}  # peer_id -> shared_secret
        
        # Roteamento
        self.routing_table = {}  # destination_ip -> peer_id
        self.local_routes = [str(self.vpn_network)]
        
        # Estado da VPN
        self.running = False
        self.server_port = 8443
        
        # Threads
        self.tun_reader_thread = None
        self.packet_processor_thread = None
        self.server_thread = None
        
        # Estatísticas
        self.stats = {
            'packets_sent': 0,
            'packets_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'peers_connected': 0,
            'encryption_operations': 0
        }
        
        # Configurações de segurança
        self.encryption_algorithm = algorithms.AES
        self.key_size = 256 // 8  # 32 bytes
        self.iv_size = 16  # 128 bits
        
    def _derive_public_key(self, private_key: bytes) -> bytes:
        """Deriva chave pública da privada (simplificado)"""
        # Em produção, usar ECDH ou similar
        return hashlib.sha256(private_key + b"public").digest()
    
    def _derive_shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        """Deriva segredo compartilhado"""
        # Implementação simplificada de ECDH
        combined = private_key + peer_public_key
        return hashlib.sha256(combined).digest()
    
    def _encrypt_packet(self, data: bytes, shared_secret: bytes) -> Tuple[bytes, bytes]:
        """Criptografa pacote"""
        try:
            # Gerar IV aleatório
            iv = secrets.token_bytes(self.iv_size)
            
            # Criar cipher
            cipher = Cipher(
                self.encryption_algorithm(shared_secret),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Padding PKCS7
            padding_length = 16 - (len(data) % 16)
            padded_data = data + bytes([padding_length] * padding_length)
            
            # Criptografar
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Calcular HMAC
            hmac_key = hashlib.sha256(shared_secret + b"hmac").digest()
            hmac_tag = hmac.new(hmac_key, iv + encrypted_data, hashlib.sha256).digest()
            
            self.stats['encryption_operations'] += 1
            
            return iv + encrypted_data, hmac_tag
            
        except Exception as e:
            logger.error(f"Erro na criptografia: {e}")
            return b"", b""
    
    def _decrypt_packet(self, encrypted_data: bytes, hmac_tag: bytes, shared_secret: bytes) -> Optional[bytes]:
        """Descriptografa pacote"""
        try:
            if len(encrypted_data) < self.iv_size:
                return None
            
            # Extrair IV
            iv = encrypted_data[:self.iv_size]
            ciphertext = encrypted_data[self.iv_size:]
            
            # Verificar HMAC
            hmac_key = hashlib.sha256(shared_secret + b"hmac").digest()
            expected_hmac = hmac.new(hmac_key, encrypted_data, hashlib.sha256).digest()
            
            if not hmac.compare_digest(hmac_tag, expected_hmac):
                logger.warning("HMAC inválido - pacote rejeitado")
                return None
            
            # Descriptografar
            cipher = Cipher(
                self.encryption_algorithm(shared_secret),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remover padding
            padding_length = padded_data[-1]
            if padding_length > 16:
                return None
            
            data = padded_data[:-padding_length]
            
            self.stats['encryption_operations'] += 1
            
            return data
            
        except Exception as e:
            logger.error(f"Erro na descriptografia: {e}")
            return None
    
    def add_peer(self, peer_id: str, peer_public_key: bytes, external_ip: str, external_port: int, vpn_ip: str):
        """Adiciona peer à VPN"""
        try:
            # Derivar segredo compartilhado
            shared_secret = self._derive_shared_secret(self.local_private_key, peer_public_key)
            self.peer_keys[peer_id] = shared_secret
            
            # Criar objeto peer
            peer = VPNPeer(
                peer_id=peer_id,
                public_key=peer_public_key,
                vpn_ip=vpn_ip,
                external_ip=external_ip,
                external_port=external_port,
                last_seen=time.time()
            )
            
            self.peers[peer_id] = peer
            
            # Adicionar rota
            self.routing_table[vpn_ip] = peer_id
            
            self.stats['peers_connected'] += 1
            logger.info(f"Peer adicionado: {peer_id[:16]}... ({vpn_ip})")
            
        except Exception as e:
            logger.error(f"Erro ao adicionar peer: {e}")
    
    def connect_to_peer(self, peer_info: Dict) -> bool:
        """Conecta a um peer"""
        try:
            peer_id = peer_info['peer_id']
            external_ip = peer_info['external_ip']
            external_port = peer_info['external_port']
            
            # Criar socket UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            
            # Handshake inicial
            handshake_data = {
                'type': 'vpn_handshake',
                'peer_id': self.get_local_peer_id(),
                'public_key': self.local_public_key.hex(),
                'vpn_ip': self.local_vpn_ip,
                'timestamp': time.time()
            }
            
            handshake_packet = json.dumps(handshake_data).encode('utf-8')
            sock.sendto(handshake_packet, (external_ip, external_port))
            
            # Aguardar resposta
            response_data, addr = sock.recvfrom(4096)
            response = json.loads(response_data.decode('utf-8'))
            
            if response.get('type') == 'vpn_handshake_ack':
                # Adicionar peer
                self.add_peer(
                    peer_id=response['peer_id'],
                    peer_public_key=bytes.fromhex(response['public_key']),
                    external_ip=external_ip,
                    external_port=external_port,
                    vpn_ip=response['vpn_ip']
                )
                
                # Armazenar socket
                self.peer_sockets[peer_id] = sock
                
                logger.info(f"Conectado ao peer: {peer_id[:16]}...")
                return True
            
        except Exception as e:
            logger.error(f"Erro ao conectar ao peer: {e}")
        
        return False
    
    def start_vpn_server(self):
        """Inicia servidor VPN para aceitar conexões"""
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_sock.bind(('0.0.0.0', self.server_port))
            
            logger.info(f"Servidor VPN iniciado na porta {self.server_port}")
            
            while self.running:
                try:
                    data, addr = server_sock.recvfrom(4096)
                    
                    # Processar em thread separada
                    threading.Thread(
                        target=self.handle_vpn_message,
                        args=(data, addr, server_sock),
                        daemon=True
                    ).start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Erro no servidor VPN: {e}")
            
        except Exception as e:
            logger.error(f"Erro ao iniciar servidor VPN: {e}")
        finally:
            if 'server_sock' in locals():
                server_sock.close()
    
    def handle_vpn_message(self, data: bytes, addr: Tuple[str, int], server_sock: socket.socket):
        """Processa mensagem VPN recebida"""
        try:
            # Tentar parse como JSON (handshake)
            try:
                message = json.loads(data.decode('utf-8'))
                
                if message.get('type') == 'vpn_handshake':
                    # Responder handshake
                    response = {
                        'type': 'vpn_handshake_ack',
                        'peer_id': self.get_local_peer_id(),
                        'public_key': self.local_public_key.hex(),
                        'vpn_ip': self.local_vpn_ip,
                        'timestamp': time.time()
                    }
                    
                    response_packet = json.dumps(response).encode('utf-8')
                    server_sock.sendto(response_packet, addr)
                    
                    # Adicionar peer
                    self.add_peer(
                        peer_id=message['peer_id'],
                        peer_public_key=bytes.fromhex(message['public_key']),
                        external_ip=addr[0],
                        external_port=addr[1],
                        vpn_ip=message['vpn_ip']
                    )
                    
                    return
                    
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            
            # Processar como pacote VPN encriptado
            self.process_encrypted_packet(data, addr)
            
        except Exception as e:
            logger.error(f"Erro ao processar mensagem VPN: {e}")
    
    def process_encrypted_packet(self, data: bytes, addr: Tuple[str, int]):
        """Processa pacote VPN encriptado"""
        try:
            if len(data) < 64:  # Tamanho mínimo
                return
            
            # Parse header do pacote VPN
            # Formato: peer_id(32) + sequence(4) + timestamp(8) + hmac(32) + encrypted_data
            peer_id = data[:32].hex()
            sequence = struct.unpack('!I', data[32:36])[0]
            timestamp = struct.unpack('!d', data[36:44])[0]
            hmac_tag = data[44:76]
            encrypted_data = data[76:]
            
            # Verificar se conhecemos este peer
            if peer_id not in self.peer_keys:
                logger.warning(f"Pacote de peer desconhecido: {peer_id[:16]}...")
                return
            
            # Descriptografar
            shared_secret = self.peer_keys[peer_id]
            decrypted_data = self._decrypt_packet(encrypted_data, hmac_tag, shared_secret)
            
            if decrypted_data:
                # Escrever na interface TUN
                if self.tun_interface.write_packet(decrypted_data):
                    self.stats['packets_received'] += 1
                    self.stats['bytes_received'] += len(decrypted_data)
                    
                    # Atualizar last_seen do peer
                    if peer_id in self.peers:
                        self.peers[peer_id].last_seen = time.time()
            
        except Exception as e:
            logger.error(f"Erro ao processar pacote encriptado: {e}")
    
    def tun_reader_loop(self):
        """Loop de leitura da interface TUN"""
        while self.running:
            try:
                # Ler pacote da interface TUN
                packet = self.tun_interface.read_packet()
                if not packet:
                    time.sleep(0.01)
                    continue
                
                # Processar pacote IP
                self.route_packet(packet)
                
            except Exception as e:
                logger.error(f"Erro no loop TUN: {e}")
                time.sleep(1)
    
    def route_packet(self, packet: bytes):
        """Roteia pacote IP através da VPN"""
        try:
            if len(packet) < 20:  # Tamanho mínimo IP header
                return
            
            # Parse header IP
            version_ihl = packet[0]
            version = (version_ihl >> 4) & 0xF
            
            if version != 4:  # Apenas IPv4 por enquanto
                return
            
            # Extrair IP de destino
            dest_ip = socket.inet_ntoa(packet[16:20])
            
            # Encontrar peer para roteamento
            target_peer_id = self.routing_table.get(dest_ip)
            
            if target_peer_id and target_peer_id in self.peers:
                # Enviar para peer específico
                self.send_packet_to_peer(packet, target_peer_id)
            else:
                # Broadcast para todos os peers (flooding)
                for peer_id in self.peers:
                    self.send_packet_to_peer(packet, peer_id)
            
        except Exception as e:
            logger.error(f"Erro no roteamento: {e}")
    
    def send_packet_to_peer(self, packet: bytes, peer_id: str):
        """Envia pacote para peer específico"""
        try:
            if peer_id not in self.peers or peer_id not in self.peer_keys:
                return
            
            peer = self.peers[peer_id]
            shared_secret = self.peer_keys[peer_id]
            
            # Criptografar pacote
            encrypted_data, hmac_tag = self._encrypt_packet(packet, shared_secret)
            
            if not encrypted_data:
                return
            
            # Criar header VPN
            peer_id_bytes = bytes.fromhex(peer_id)[:32]
            if len(peer_id_bytes) < 32:
                peer_id_bytes += b'\x00' * (32 - len(peer_id_bytes))
            
            sequence = self.stats['packets_sent'] % (2**32)
            timestamp = time.time()
            
            header = peer_id_bytes
            header += struct.pack('!I', sequence)
            header += struct.pack('!d', timestamp)
            header += hmac_tag
            
            # Pacote final
            vpn_packet = header + encrypted_data
            
            # Enviar via socket
            if peer_id in self.peer_sockets:
                sock = self.peer_sockets[peer_id]
                sock.sendto(vpn_packet, (peer.external_ip, peer.external_port))
                
                self.stats['packets_sent'] += 1
                self.stats['bytes_sent'] += len(packet)
            
        except Exception as e:
            logger.error(f"Erro ao enviar pacote: {e}")
    
    def get_local_peer_id(self) -> str:
        """Obtém ID do peer local"""
        return hashlib.sha256(self.local_public_key).hexdigest()
    
    def start(self) -> bool:
        """Inicia VPN P2P"""
        try:
            # Criar interface TUN
            if not self.tun_interface.create_tun_interface():
                logger.error("Falha ao criar interface TUN")
                return False
            
            self.running = True
            
            # Iniciar threads
            self.tun_reader_thread = threading.Thread(target=self.tun_reader_loop, daemon=True)
            self.tun_reader_thread.start()
            
            self.server_thread = threading.Thread(target=self.start_vpn_server, daemon=True)
            self.server_thread.start()
            
            logger.info(f"VPN P2P iniciada - IP local: {self.local_vpn_ip}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao iniciar VPN: {e}")
            return False
    
    def stop(self):
        """Para VPN P2P"""
        self.running = False
        
        # Fechar interface TUN
        self.tun_interface.close()
        
        # Fechar sockets dos peers
        for sock in self.peer_sockets.values():
            try:
                sock.close()
            except:
                pass
        
        logger.info("VPN P2P parada")
    
    def get_stats(self) -> Dict:
        """Obtém estatísticas da VPN"""
        return {
            'local_vpn_ip': self.local_vpn_ip,
            'vpn_network': str(self.vpn_network),
            'peers_connected': len(self.peers),
            'routes_active': len(self.routing_table),
            'packets_sent': self.stats['packets_sent'],
            'packets_received': self.stats['packets_received'],
            'bytes_sent': self.stats['bytes_sent'],
            'bytes_received': self.stats['bytes_received'],
            'encryption_operations': self.stats['encryption_operations'],
            'running': self.running
        }
    
    def get_peer_info(self) -> List[Dict]:
        """Obtém informações dos peers"""
        peer_info = []
        
        for peer_id, peer in self.peers.items():
            info = {
                'peer_id': peer_id[:16] + "...",
                'vpn_ip': peer.vpn_ip,
                'external_ip': peer.external_ip,
                'external_port': peer.external_port,
                'last_seen': peer.last_seen,
                'connected': time.time() - peer.last_seen < 60
            }
            peer_info.append(info)
        
        return peer_info

def test_p2p_vpn():
    """Teste do sistema VPN P2P"""
    print("🛡️ Testando QuantumP2PVPN...")
    
    # Verificar se está rodando como root (necessário para TUN)
    if os.geteuid() != 0:
        print("⚠️ Teste VPN requer privilégios root para criar interface TUN")
        print("✅ Testando apenas funcionalidades básicas...")
        
        vpn = QuantumP2PVPN()
        
        # Teste de criptografia
        print("\n🔐 Testando criptografia...")
        test_data = b"Hello, QuantumVPN!"
        shared_secret = secrets.token_bytes(32)
        
        encrypted, hmac_tag = vpn._encrypt_packet(test_data, shared_secret)
        decrypted = vpn._decrypt_packet(encrypted, hmac_tag, shared_secret)
        
        if decrypted == test_data:
            print("✅ Criptografia funcionando")
        else:
            print("❌ Erro na criptografia")
        
        # Teste de peer management
        print("\n👥 Testando gerenciamento de peers...")
        peer_public_key = secrets.token_bytes(32)
        vpn.add_peer("test_peer", peer_public_key, "192.168.1.100", 8443, "10.42.0.2")
        
        stats = vpn.get_stats()
        print(f"✅ Peers conectados: {stats['peers_connected']}")
        
        peer_info = vpn.get_peer_info()
        print(f"✅ Info dos peers: {len(peer_info)} peers")
        
        print("\n📊 Estatísticas:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        print("\n✅ Teste VPN P2P concluído (modo limitado)")
        return True
    
    else:
        # Teste completo com interface TUN
        print("\n🔧 Testando com interface TUN...")
        
        vpn = QuantumP2PVPN(local_vpn_ip="10.42.0.1")
        
        try:
            if vpn.start():
                print("✅ VPN iniciada com sucesso")
                
                # Aguardar um pouco
                time.sleep(2)
                
                # Verificar estatísticas
                stats = vpn.get_stats()
                print(f"✅ VPN rodando: {stats['running']}")
                print(f"✅ IP VPN: {stats['local_vpn_ip']}")
                
                vpn.stop()
                print("✅ VPN parada")
                
                return True
            else:
                print("❌ Falha ao iniciar VPN")
                return False
                
        except Exception as e:
            print(f"❌ Erro no teste: {e}")
            return False

if __name__ == "__main__":
    test_p2p_vpn()

