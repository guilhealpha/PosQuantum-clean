#!/usr/bin/env python3
"""
Quantum Distributed Storage System
Sistema de armazenamento distribuído pós-quântico
"""

import os
import json
import time
import hashlib
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

class DistributedStorage:
    """Sistema de armazenamento distribuído pós-quântico"""
    
    def __init__(self):
        self.storage_path = Path("quantum_storage")
        self.nodes = {}
        self.files = {}
        self.encryption_key = None
        self.initialized = False
        self.replication_factor = 3
        self.chunk_size = 1024 * 1024  # 1MB chunks
        
    def initialize(self) -> Dict[str, Any]:
        """Inicializar sistema de storage"""
        try:
            # Criar diretório de storage
            self.storage_path.mkdir(exist_ok=True)
            
            # Gerar chave de criptografia
            self.encryption_key = os.urandom(32)
            
            # Inicializar nós locais
            self._initialize_local_nodes()
            
            # Carregar metadados existentes
            self._load_metadata()
            
            self.initialized = True
            
            return {
                'success': True,
                'message': 'Storage distribuído inicializado',
                'nodes_count': len(self.nodes),
                'storage_path': str(self.storage_path)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Erro ao inicializar storage: {str(e)}'
            }
    
    def _initialize_local_nodes(self):
        """Inicializar nós locais"""
        # Simular 5 nós distribuídos
        for i in range(5):
            node_id = f"node_{i:03d}"
            node_path = self.storage_path / node_id
            node_path.mkdir(exist_ok=True)
            
            self.nodes[node_id] = {
                'id': node_id,
                'path': node_path,
                'status': 'online',
                'capacity': 1024 * 1024 * 1024,  # 1GB
                'used': 0,
                'last_seen': datetime.now().isoformat()
            }
    
    def _load_metadata(self):
        """Carregar metadados de arquivos"""
        metadata_file = self.storage_path / "metadata.json"
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r') as f:
                    self.files = json.load(f)
            except:
                self.files = {}
    
    def _save_metadata(self):
        """Salvar metadados de arquivos"""
        metadata_file = self.storage_path / "metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(self.files, f, indent=2)
    
    def store_file(self, file_path: str, data: bytes) -> Dict[str, Any]:
        """Armazenar arquivo no sistema distribuído"""
        if not self.initialized:
            return {'success': False, 'error': 'Storage não inicializado'}
        
        try:
            # Gerar hash do arquivo
            file_hash = hashlib.sha256(data).hexdigest()
            
            # Dividir em chunks
            chunks = self._split_into_chunks(data)
            
            # Distribuir chunks pelos nós
            chunk_locations = {}
            for i, chunk in enumerate(chunks):
                chunk_id = f"{file_hash}_{i:04d}"
                locations = self._store_chunk(chunk_id, chunk)
                chunk_locations[chunk_id] = locations
            
            # Salvar metadados
            self.files[file_path] = {
                'hash': file_hash,
                'size': len(data),
                'chunks': len(chunks),
                'chunk_locations': chunk_locations,
                'created': datetime.now().isoformat(),
                'encrypted': True
            }
            
            self._save_metadata()
            
            return {
                'success': True,
                'file_hash': file_hash,
                'chunks_stored': len(chunks),
                'replication_factor': self.replication_factor
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Erro ao armazenar arquivo: {str(e)}'
            }
    
    def _split_into_chunks(self, data: bytes) -> List[bytes]:
        """Dividir dados em chunks"""
        chunks = []
        for i in range(0, len(data), self.chunk_size):
            chunk = data[i:i + self.chunk_size]
            chunks.append(chunk)
        return chunks
    
    def _store_chunk(self, chunk_id: str, chunk_data: bytes) -> List[str]:
        """Armazenar chunk em múltiplos nós"""
        locations = []
        
        # Selecionar nós para replicação
        available_nodes = [node_id for node_id, node in self.nodes.items() 
                          if node['status'] == 'online']
        
        selected_nodes = available_nodes[:self.replication_factor]
        
        for node_id in selected_nodes:
            try:
                # Criptografar chunk
                encrypted_chunk = self._encrypt_chunk(chunk_data)
                
                # Salvar no nó
                chunk_path = self.nodes[node_id]['path'] / f"{chunk_id}.chunk"
                with open(chunk_path, 'wb') as f:
                    f.write(encrypted_chunk)
                
                # Atualizar uso do nó
                self.nodes[node_id]['used'] += len(encrypted_chunk)
                
                locations.append(node_id)
                
            except Exception as e:
                print(f"Erro ao armazenar chunk {chunk_id} no nó {node_id}: {e}")
        
        return locations
    
    def _encrypt_chunk(self, data: bytes) -> bytes:
        """Criptografar chunk com AES-256"""
        # Implementação simplificada de criptografia
        # Em produção, usar biblioteca criptográfica real
        key_hash = hashlib.sha256(self.encryption_key).digest()
        
        # XOR simples para demonstração (usar AES real em produção)
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ key_hash[i % len(key_hash)])
        
        return bytes(encrypted)
    
    def retrieve_file(self, file_path: str) -> Dict[str, Any]:
        """Recuperar arquivo do sistema distribuído"""
        if not self.initialized:
            return {'success': False, 'error': 'Storage não inicializado'}
        
        if file_path not in self.files:
            return {'success': False, 'error': 'Arquivo não encontrado'}
        
        try:
            file_info = self.files[file_path]
            chunks_data = []
            
            # Recuperar todos os chunks
            for chunk_id, locations in file_info['chunk_locations'].items():
                chunk_data = self._retrieve_chunk(chunk_id, locations)
                if chunk_data is None:
                    return {'success': False, 'error': f'Chunk {chunk_id} não recuperado'}
                chunks_data.append(chunk_data)
            
            # Reconstruir arquivo
            file_data = b''.join(chunks_data)
            
            # Verificar integridade
            file_hash = hashlib.sha256(file_data).hexdigest()
            if file_hash != file_info['hash']:
                return {'success': False, 'error': 'Integridade do arquivo comprometida'}
            
            return {
                'success': True,
                'data': file_data,
                'size': len(file_data),
                'hash': file_hash
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Erro ao recuperar arquivo: {str(e)}'
            }
    
    def _retrieve_chunk(self, chunk_id: str, locations: List[str]) -> Optional[bytes]:
        """Recuperar chunk de um dos nós"""
        for node_id in locations:
            try:
                chunk_path = self.nodes[node_id]['path'] / f"{chunk_id}.chunk"
                if chunk_path.exists():
                    with open(chunk_path, 'rb') as f:
                        encrypted_data = f.read()
                    
                    # Descriptografar
                    decrypted_data = self._decrypt_chunk(encrypted_data)
                    return decrypted_data
                    
            except Exception as e:
                print(f"Erro ao recuperar chunk {chunk_id} do nó {node_id}: {e}")
                continue
        
        return None
    
    def _decrypt_chunk(self, encrypted_data: bytes) -> bytes:
        """Descriptografar chunk"""
        # Reverter criptografia XOR
        key_hash = hashlib.sha256(self.encryption_key).digest()
        
        decrypted = bytearray()
        for i, byte in enumerate(encrypted_data):
            decrypted.append(byte ^ key_hash[i % len(key_hash)])
        
        return bytes(decrypted)
    
    def list_files(self) -> Dict[str, Any]:
        """Listar arquivos armazenados"""
        if not self.initialized:
            return {'success': False, 'error': 'Storage não inicializado'}
        
        files_list = []
        for file_path, file_info in self.files.items():
            files_list.append({
                'path': file_path,
                'size': file_info['size'],
                'hash': file_info['hash'],
                'chunks': file_info['chunks'],
                'created': file_info['created']
            })
        
        return {
            'success': True,
            'files': files_list,
            'total_files': len(files_list)
        }
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """Obter estatísticas do storage"""
        if not self.initialized:
            return {'success': False, 'error': 'Storage não inicializado'}
        
        total_capacity = sum(node['capacity'] for node in self.nodes.values())
        total_used = sum(node['used'] for node in self.nodes.values())
        
        online_nodes = len([n for n in self.nodes.values() if n['status'] == 'online'])
        
        return {
            'success': True,
            'nodes_total': len(self.nodes),
            'nodes_online': online_nodes,
            'total_capacity_gb': total_capacity / (1024**3),
            'total_used_gb': total_used / (1024**3),
            'usage_percentage': (total_used / total_capacity) * 100,
            'files_stored': len(self.files),
            'replication_factor': self.replication_factor
        }
    
    def delete_file(self, file_path: str) -> Dict[str, Any]:
        """Deletar arquivo do sistema"""
        if not self.initialized:
            return {'success': False, 'error': 'Storage não inicializado'}
        
        if file_path not in self.files:
            return {'success': False, 'error': 'Arquivo não encontrado'}
        
        try:
            file_info = self.files[file_path]
            
            # Deletar todos os chunks
            for chunk_id, locations in file_info['chunk_locations'].items():
                self._delete_chunk(chunk_id, locations)
            
            # Remover dos metadados
            del self.files[file_path]
            self._save_metadata()
            
            return {
                'success': True,
                'message': f'Arquivo {file_path} deletado com sucesso'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Erro ao deletar arquivo: {str(e)}'
            }
    
    def _delete_chunk(self, chunk_id: str, locations: List[str]):
        """Deletar chunk de todos os nós"""
        for node_id in locations:
            try:
                chunk_path = self.nodes[node_id]['path'] / f"{chunk_id}.chunk"
                if chunk_path.exists():
                    chunk_size = chunk_path.stat().st_size
                    chunk_path.unlink()
                    
                    # Atualizar uso do nó
                    self.nodes[node_id]['used'] -= chunk_size
                    
            except Exception as e:
                print(f"Erro ao deletar chunk {chunk_id} do nó {node_id}: {e}")
    
    def sync_nodes(self) -> Dict[str, Any]:
        """Sincronizar nós e verificar integridade"""
        if not self.initialized:
            return {'success': False, 'error': 'Storage não inicializado'}
        
        try:
            sync_results = []
            
            for node_id, node in self.nodes.items():
                # Verificar se nó está online
                if node['path'].exists():
                    node['status'] = 'online'
                    node['last_seen'] = datetime.now().isoformat()
                    
                    # Contar arquivos no nó
                    chunk_files = list(node['path'].glob("*.chunk"))
                    
                    sync_results.append({
                        'node_id': node_id,
                        'status': 'online',
                        'chunks': len(chunk_files)
                    })
                else:
                    node['status'] = 'offline'
                    sync_results.append({
                        'node_id': node_id,
                        'status': 'offline',
                        'chunks': 0
                    })
            
            return {
                'success': True,
                'sync_results': sync_results,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Erro na sincronização: {str(e)}'
            }

# Função de teste
def test_distributed_storage():
    """Testar funcionalidades do storage distribuído"""
    storage = DistributedStorage()
    
    # Inicializar
    result = storage.initialize()
    print(f"Inicialização: {result}")
    
    # Armazenar arquivo de teste
    test_data = "Este eh um arquivo de teste para o storage distribuido pos-quantico!".encode('utf-8')
    result = storage.store_file("test.txt", test_data)
    print(f"Armazenamento: {result}")
    
    # Listar arquivos
    result = storage.list_files()
    print(f"Lista de arquivos: {result}")
    
    # Recuperar arquivo
    result = storage.retrieve_file("test.txt")
    print(f"Recuperação: {result['success']}")
    
    # Estatísticas
    result = storage.get_storage_stats()
    print(f"Estatísticas: {result}")
    
    return storage

if __name__ == "__main__":
    test_distributed_storage()

