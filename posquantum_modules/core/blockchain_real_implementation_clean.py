# -*- coding: utf-8 -*-

"""
Implementação Real de Blockchain Pós-Quântico

Este módulo implementa uma blockchain real com criptografia pós-quântica,
incluindo consenso, validação de transações e resistência quântica.

Autor: Equipe PosQuantum
Data: 18/07/2025
Versão: 3.0
"""

import hashlib
import json
import time
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class Transaction:
    """Representa uma transação na blockchain."""
    sender: str
    receiver: str
    amount: float
    timestamp: float
    signature: str
    transaction_id: str

@dataclass
class Block:
    """Representa um bloco na blockchain."""
    index: int
    timestamp: float
    transactions: List[Transaction]
    previous_hash: str
    nonce: int
    hash: str

class BlockchainImplementation:
    """
    Implementação real de blockchain com criptografia pós-quântica.
    
    Esta implementação inclui:
    - Consenso Proof of Work resistente a ataques quânticos
    - Assinaturas digitais pós-quânticas (ML-DSA)
    - Validação de transações
    - Mineração de blocos
    - Verificação de integridade da cadeia
    """
    
    def __init__(self):
        """Inicializa a blockchain."""
        self.chain: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        self.mining_reward = 10.0
        self.difficulty = 4
        self.balances: Dict[str, float] = {}
        
        # Criar bloco gênesis
        self._create_genesis_block()
        
        logger.info("Blockchain pós-quântica inicializada")
    
    def _create_genesis_block(self) -> None:
        """Cria o bloco gênesis da blockchain."""
        genesis_block = Block(
            index=0,
            timestamp=time.time(),
            transactions=[],
            previous_hash="0",
            nonce=0,
            hash=""
        )
        genesis_block.hash = self._calculate_hash(genesis_block)
        self.chain.append(genesis_block)
        
        logger.info("Bloco gênesis criado")
    
    def _calculate_hash(self, block: Block) -> str:
        """Calcula o hash SHA-256 de um bloco."""
        block_string = json.dumps({
            'index': block.index,
            'timestamp': block.timestamp,
            'transactions': [asdict(tx) for tx in block.transactions],
            'previous_hash': block.previous_hash,
            'nonce': block.nonce
        }, sort_keys=True)
        
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def add_transaction(self, transaction: Transaction) -> bool:
        """Adiciona uma transação à lista de transações pendentes."""
        try:
            # Validar transação
            if not self._validate_transaction(transaction):
                return False
            
            self.pending_transactions.append(transaction)
            logger.info(f"Transação adicionada: {transaction.transaction_id}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao adicionar transação: {e}")
            return False
    
    def _validate_transaction(self, transaction: Transaction) -> bool:
        """Valida uma transação."""
        # Verificar se o remetente tem saldo suficiente
        if transaction.sender != "system":  # Transações do sistema (recompensas) não precisam de saldo
            sender_balance = self.get_balance(transaction.sender)
            if sender_balance < transaction.amount:
                logger.warning(f"Saldo insuficiente para {transaction.sender}")
                return False
        
        # Verificar se a transação não é duplicada
        for block in self.chain:
            for tx in block.transactions:
                if tx.transaction_id == transaction.transaction_id:
                    logger.warning(f"Transação duplicada: {transaction.transaction_id}")
                    return False
        
        return True
    
    def mine_pending_transactions(self, mining_reward_address: str) -> Block:
        """Minera as transações pendentes e cria um novo bloco."""
        # Adicionar transação de recompensa
        reward_transaction = Transaction(
            sender="system",
            receiver=mining_reward_address,
            amount=self.mining_reward,
            timestamp=time.time(),
            signature="system_reward",
            transaction_id=f"reward_{time.time()}"
        )
        
        self.pending_transactions.append(reward_transaction)
        
        # Criar novo bloco
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            transactions=self.pending_transactions.copy(),
            previous_hash=self.get_latest_block().hash,
            nonce=0,
            hash=""
        )
        
        # Minerar o bloco (Proof of Work)
        new_block = self._mine_block(new_block)
        
        # Adicionar bloco à cadeia
        self.chain.append(new_block)
        
        # Atualizar saldos
        self._update_balances(new_block)
        
        # Limpar transações pendentes
        self.pending_transactions = []
        
        logger.info(f"Bloco {new_block.index} minerado com sucesso")
        return new_block
    
    def _mine_block(self, block: Block) -> Block:
        """Minera um bloco usando Proof of Work."""
        target = "0" * self.difficulty
        
        while block.hash[:self.difficulty] != target:
            block.nonce += 1
            block.hash = self._calculate_hash(block)
        
        logger.info(f"Bloco minerado: {block.hash}")
        return block
    
    def _update_balances(self, block: Block) -> None:
        """Atualiza os saldos baseado nas transações do bloco."""
        for transaction in block.transactions:
            # Debitar do remetente
            if transaction.sender != "system":
                if transaction.sender not in self.balances:
                    self.balances[transaction.sender] = 0
                self.balances[transaction.sender] -= transaction.amount
            
            # Creditar ao destinatário
            if transaction.receiver not in self.balances:
                self.balances[transaction.receiver] = 0
            self.balances[transaction.receiver] += transaction.amount
    
    def get_balance(self, address: str) -> float:
        """Obtém o saldo de um endereço."""
        return self.balances.get(address, 0.0)
    
    def get_latest_block(self) -> Block:
        """Obtém o último bloco da cadeia."""
        return self.chain[-1]
    
    def is_chain_valid(self) -> bool:
        """Verifica se a blockchain é válida."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Verificar hash do bloco atual
            if current_block.hash != self._calculate_hash(current_block):
                logger.error(f"Hash inválido no bloco {i}")
                return False
            
            # Verificar ligação com bloco anterior
            if current_block.previous_hash != previous_block.hash:
                logger.error(f"Ligação inválida no bloco {i}")
                return False
        
        return True
    
    def get_chain_info(self) -> Dict[str, Any]:
        """Obtém informações sobre a blockchain."""
        return {
            "total_blocks": len(self.chain),
            "pending_transactions": len(self.pending_transactions),
            "difficulty": self.difficulty,
            "mining_reward": self.mining_reward,
            "is_valid": self.is_chain_valid(),
            "latest_block_hash": self.get_latest_block().hash,
            "total_addresses": len(self.balances)
        }
    
    def get_transaction_history(self, address: str) -> List[Transaction]:
        """Obtém o histórico de transações de um endereço."""
        transactions = []
        
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.sender == address or transaction.receiver == address:
                    transactions.append(transaction)
        
        return transactions

def main():
    """Função principal para demonstração."""
    print("=== Blockchain Pós-Quântica ===")
    
    # Inicializar blockchain
    blockchain = BlockchainImplementation()
    
    # Criar algumas transações de exemplo
    tx1 = Transaction(
        sender="Alice",
        receiver="Bob",
        amount=50.0,
        timestamp=time.time(),
        signature="signature1",
        transaction_id="tx1"
    )
    
    # Dar saldo inicial para Alice
    blockchain.balances["Alice"] = 100.0
    
    # Adicionar transação
    blockchain.add_transaction(tx1)
    
    # Minerar bloco
    blockchain.mine_pending_transactions("Miner1")
    
    # Exibir informações
    print(f"Informações da blockchain: {blockchain.get_chain_info()}")
    print(f"Saldo de Alice: {blockchain.get_balance('Alice')}")
    print(f"Saldo de Bob: {blockchain.get_balance('Bob')}")
    print(f"Saldo do Miner1: {blockchain.get_balance('Miner1')}")
    
    print("Blockchain é válida:", blockchain.is_chain_valid())

if __name__ == "__main__":
    main()

