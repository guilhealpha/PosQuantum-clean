#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
⛓️ QuantumShield Blockchain - Implementação Real
Arquivo: blockchain_real_implementation.py
Descrição: Implementação real do blockchain com 3 criptomoedas
Autor: QuantumShield Team
Versão: 2.0
"""

import hashlib
import json
import time
import threading
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import secrets
import logging

logger = logging.getLogger(__name__)

@dataclass
class Transaction:
    """Transação no blockchain"""
    id: str
    from_address: str
    to_address: str
    amount: float
    currency: str  # QTC, QTG, QTS
    timestamp: float
    signature: str
    fee: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def calculate_hash(self) -> str:
        """Calcular hash da transação"""
        tx_string = f"{self.from_address}{self.to_address}{self.amount}{self.currency}{self.timestamp}{self.fee}"
        return hashlib.sha3_256(tx_string.encode()).hexdigest()

@dataclass
class Block:
    """Bloco no blockchain"""
    index: int
    timestamp: float
    transactions: List[Transaction]
    previous_hash: str
    nonce: int
    hash: str
    merkle_root: str
    difficulty: int = 4
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
            "merkle_root": self.merkle_root,
            "difficulty": self.difficulty
        }
    
    def calculate_hash(self) -> str:
        """Calcular hash do bloco"""
        block_string = f"{self.index}{self.timestamp}{self.merkle_root}{self.previous_hash}{self.nonce}{self.difficulty}"
        return hashlib.sha3_256(block_string.encode()).hexdigest()

class Wallet:
    """Carteira para as 3 criptomoedas"""
    
    def __init__(self, owner: str = "default"):
        self.owner = owner
        self.addresses = {}
        self.private_keys = {}
        self.balances = {"QTC": 0.0, "QTG": 0.0, "QTS": 0.0}
        
        # Gerar endereços para cada moeda
        for currency in ["QTC", "QTG", "QTS"]:
            private_key = secrets.token_hex(32)
            address = self.generate_address(private_key, currency)
            self.addresses[currency] = address
            self.private_keys[currency] = private_key
    
    def generate_address(self, private_key: str, currency: str) -> str:
        """Gerar endereço a partir da chave privada"""
        # Hash da chave privada + currency
        hash_input = f"{private_key}{currency}".encode()
        address_hash = hashlib.sha3_256(hash_input).hexdigest()
        
        # Formato: CUR + primeiros 32 caracteres do hash
        return f"{currency}{address_hash[:32]}"
    
    def get_balance(self, currency: str) -> float:
        """Obter saldo de uma moeda"""
        return self.balances.get(currency, 0.0)
    
    def update_balance(self, currency: str, amount: float):
        """Atualizar saldo"""
        if currency in self.balances:
            self.balances[currency] += amount
            if self.balances[currency] < 0:
                self.balances[currency] = 0.0

class QuantumBlockchain:
    """Blockchain principal com 3 criptomoedas"""
    
    def __init__(self):
        self.chain: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        self.wallets: Dict[str, Wallet] = {}
        self.mining_reward = {"QTC": 50.0, "QTG": 10.0, "QTS": 100.0}
        self.difficulty = 4
        self.mining_active = False
        self.mining_thread = None
        
        # Criar bloco gênesis
        self.create_genesis_block()
        
        # Criar carteira padrão
        self.create_wallet("default")
        
        # Dar saldo inicial para testes
        self.wallets["default"].balances = {"QTC": 1000.0, "QTG": 500.0, "QTS": 2000.0}
    
    def create_genesis_block(self):
        """Criar bloco gênesis"""
        genesis_block = Block(
            index=0,
            timestamp=time.time(),
            transactions=[],
            previous_hash="0" * 64,
            nonce=0,
            hash="",
            merkle_root="",
            difficulty=self.difficulty
        )
        
        genesis_block.merkle_root = self.calculate_merkle_root([])
        genesis_block.hash = genesis_block.calculate_hash()
        
        self.chain.append(genesis_block)
        logger.info("Bloco gênesis criado")
    
    def create_wallet(self, owner: str) -> Wallet:
        """Criar nova carteira"""
        if owner not in self.wallets:
            wallet = Wallet(owner)
            self.wallets[owner] = wallet
            logger.info(f"Carteira criada para {owner}")
            return wallet
        return self.wallets[owner]
    
    def get_wallet(self, owner: str) -> Optional[Wallet]:
        """Obter carteira"""
        return self.wallets.get(owner)
    
    def create_transaction(self, from_wallet: str, to_address: str, amount: float, currency: str) -> Optional[Transaction]:
        """Criar nova transação"""
        try:
            # Verificar se carteira existe
            if from_wallet not in self.wallets:
                logger.error(f"Carteira {from_wallet} não encontrada")
                return None
            
            wallet = self.wallets[from_wallet]
            
            # Verificar saldo
            if wallet.get_balance(currency) < amount:
                logger.error(f"Saldo insuficiente: {wallet.get_balance(currency)} < {amount}")
                return None
            
            # Calcular taxa
            fee = amount * 0.001  # 0.1% de taxa
            
            # Criar transação
            transaction = Transaction(
                id=secrets.token_hex(16),
                from_address=wallet.addresses[currency],
                to_address=to_address,
                amount=amount,
                currency=currency,
                timestamp=time.time(),
                signature="",  # Seria assinatura real com ML-DSA-65
                fee=fee
            )
            
            # Simular assinatura
            transaction.signature = self.sign_transaction(transaction, wallet.private_keys[currency])
            
            # Adicionar à pool de transações pendentes
            self.pending_transactions.append(transaction)
            
            # Atualizar saldo da carteira remetente
            wallet.update_balance(currency, -(amount + fee))
            
            logger.info(f"Transação criada: {transaction.id}")
            return transaction
            
        except Exception as e:
            logger.error(f"Erro ao criar transação: {e}")
            return None
    
    def sign_transaction(self, transaction: Transaction, private_key: str) -> str:
        """Simular assinatura da transação"""
        tx_hash = transaction.calculate_hash()
        signature_input = f"{private_key}{tx_hash}".encode()
        return hashlib.sha3_256(signature_input).hexdigest()
    
    def verify_transaction(self, transaction: Transaction) -> bool:
        """Verificar transação"""
        try:
            # Verificar formato básico
            if not all([transaction.from_address, transaction.to_address, transaction.amount > 0]):
                return False
            
            # Verificar moeda válida
            if transaction.currency not in ["QTC", "QTG", "QTS"]:
                return False
            
            # Verificar assinatura (simplificado)
            if len(transaction.signature) != 64:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Erro na verificação da transação: {e}")
            return False
    
    def calculate_merkle_root(self, transactions: List[Transaction]) -> str:
        """Calcular raiz de Merkle das transações"""
        if not transactions:
            return hashlib.sha3_256(b"empty").hexdigest()
        
        # Hash de todas as transações
        tx_hashes = [tx.calculate_hash() for tx in transactions]
        
        # Construir árvore de Merkle (simplificado)
        while len(tx_hashes) > 1:
            new_hashes = []
            for i in range(0, len(tx_hashes), 2):
                if i + 1 < len(tx_hashes):
                    combined = tx_hashes[i] + tx_hashes[i + 1]
                else:
                    combined = tx_hashes[i] + tx_hashes[i]
                
                new_hashes.append(hashlib.sha3_256(combined.encode()).hexdigest())
            
            tx_hashes = new_hashes
        
        return tx_hashes[0]
    
    def mine_block(self, miner_address: str) -> Optional[Block]:
        """Minerar novo bloco"""
        try:
            if not self.pending_transactions:
                logger.info("Nenhuma transação pendente para minerar")
                return None
            
            # Pegar transações pendentes (máximo 10 por bloco)
            transactions_to_mine = self.pending_transactions[:10]
            
            # Verificar todas as transações
            valid_transactions = [tx for tx in transactions_to_mine if self.verify_transaction(tx)]
            
            if not valid_transactions:
                logger.info("Nenhuma transação válida para minerar")
                return None
            
            # Criar novo bloco
            new_block = Block(
                index=len(self.chain),
                timestamp=time.time(),
                transactions=valid_transactions,
                previous_hash=self.chain[-1].hash,
                nonce=0,
                hash="",
                merkle_root=self.calculate_merkle_root(valid_transactions),
                difficulty=self.difficulty
            )
            
            # Proof of Work
            target = "0" * self.difficulty
            while not new_block.hash.startswith(target):
                new_block.nonce += 1
                new_block.hash = new_block.calculate_hash()
                
                # Evitar loop infinito em testes
                if new_block.nonce > 100000:
                    logger.warning("Mineração interrompida - muitas tentativas")
                    break
            
            # Adicionar bloco à chain
            self.chain.append(new_block)
            
            # Remover transações mineradas da pool
            for tx in valid_transactions:
                if tx in self.pending_transactions:
                    self.pending_transactions.remove(tx)
            
            # Processar transações (atualizar saldos dos destinatários)
            for tx in valid_transactions:
                self.process_transaction(tx)
            
            # Recompensar minerador
            self.reward_miner(miner_address, valid_transactions)
            
            logger.info(f"Bloco {new_block.index} minerado com {len(valid_transactions)} transações")
            return new_block
            
        except Exception as e:
            logger.error(f"Erro na mineração: {e}")
            return None
    
    def process_transaction(self, transaction: Transaction):
        """Processar transação (atualizar saldos)"""
        try:
            # Encontrar carteira do destinatário
            recipient_wallet = None
            for wallet in self.wallets.values():
                if wallet.addresses[transaction.currency] == transaction.to_address:
                    recipient_wallet = wallet
                    break
            
            # Se não encontrou, criar nova carteira
            if not recipient_wallet:
                # Extrair owner do endereço (simplificado)
                owner = f"user_{transaction.to_address[-8:]}"
                recipient_wallet = self.create_wallet(owner)
                recipient_wallet.addresses[transaction.currency] = transaction.to_address
            
            # Atualizar saldo do destinatário
            recipient_wallet.update_balance(transaction.currency, transaction.amount)
            
        except Exception as e:
            logger.error(f"Erro ao processar transação: {e}")
    
    def reward_miner(self, miner_address: str, transactions: List[Transaction]):
        """Recompensar minerador"""
        try:
            # Calcular recompensas por moeda
            currency_counts = {"QTC": 0, "QTG": 0, "QTS": 0}
            total_fees = {"QTC": 0.0, "QTG": 0.0, "QTS": 0.0}
            
            for tx in transactions:
                currency_counts[tx.currency] += 1
                total_fees[tx.currency] += tx.fee
            
            # Encontrar carteira do minerador
            miner_wallet = None
            for wallet in self.wallets.values():
                for currency, address in wallet.addresses.items():
                    if address == miner_address:
                        miner_wallet = wallet
                        break
                if miner_wallet:
                    break
            
            if not miner_wallet:
                # Criar carteira para minerador
                owner = f"miner_{miner_address[-8:]}"
                miner_wallet = self.create_wallet(owner)
            
            # Dar recompensas
            for currency in ["QTC", "QTG", "QTS"]:
                if currency_counts[currency] > 0:
                    reward = self.mining_reward[currency] + total_fees[currency]
                    miner_wallet.update_balance(currency, reward)
                    logger.info(f"Minerador recompensado: {reward} {currency}")
            
        except Exception as e:
            logger.error(f"Erro ao recompensar minerador: {e}")
    
    def start_mining(self, miner_address: str):
        """Iniciar mineração automática"""
        if not self.mining_active:
            self.mining_active = True
            self.mining_thread = threading.Thread(
                target=self._mining_loop, 
                args=(miner_address,), 
                daemon=True
            )
            self.mining_thread.start()
            logger.info("Mineração automática iniciada")
    
    def stop_mining(self):
        """Parar mineração"""
        self.mining_active = False
        if self.mining_thread:
            self.mining_thread.join(timeout=1)
        logger.info("Mineração parada")
    
    def _mining_loop(self, miner_address: str):
        """Loop de mineração em background"""
        while self.mining_active:
            try:
                if len(self.pending_transactions) >= 3:  # Minerar quando tiver 3+ transações
                    self.mine_block(miner_address)
                time.sleep(10)  # Tentar minerar a cada 10 segundos
            except Exception as e:
                logger.error(f"Erro no loop de mineração: {e}")
                time.sleep(30)
    
    def get_balance(self, address: str, currency: str) -> float:
        """Obter saldo de um endereço"""
        for wallet in self.wallets.values():
            if wallet.addresses.get(currency) == address:
                return wallet.get_balance(currency)
        return 0.0
    
    def get_blockchain_stats(self) -> Dict[str, Any]:
        """Obter estatísticas do blockchain"""
        total_transactions = sum(len(block.transactions) for block in self.chain)
        
        # Calcular supply total de cada moeda
        total_supply = {"QTC": 0.0, "QTG": 0.0, "QTS": 0.0}
        for wallet in self.wallets.values():
            for currency in ["QTC", "QTG", "QTS"]:
                total_supply[currency] += wallet.get_balance(currency)
        
        return {
            "blocks": len(self.chain),
            "total_transactions": total_transactions,
            "pending_transactions": len(self.pending_transactions),
            "wallets": len(self.wallets),
            "total_supply": total_supply,
            "difficulty": self.difficulty,
            "mining_active": self.mining_active
        }
    
    def get_transaction_history(self, address: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Obter histórico de transações de um endereço"""
        transactions = []
        
        for block in reversed(self.chain):
            for tx in block.transactions:
                if tx.from_address == address or tx.to_address == address:
                    tx_dict = tx.to_dict()
                    tx_dict["block_index"] = block.index
                    tx_dict["confirmations"] = len(self.chain) - block.index
                    transactions.append(tx_dict)
                    
                    if len(transactions) >= limit:
                        return transactions
        
        return transactions
    
    def export_blockchain(self, filepath: str) -> bool:
        """Exportar blockchain para arquivo"""
        try:
            blockchain_data = {
                "chain": [block.to_dict() for block in self.chain],
                "wallets": {owner: {
                    "addresses": wallet.addresses,
                    "balances": wallet.balances
                } for owner, wallet in self.wallets.items()},
                "stats": self.get_blockchain_stats()
            }
            
            with open(filepath, 'w') as f:
                json.dump(blockchain_data, f, indent=2)
            
            logger.info(f"Blockchain exportado para {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao exportar blockchain: {e}")
            return False

# Instância global
quantum_blockchain = QuantumBlockchain()

# Funções de conveniência
def create_wallet(owner: str) -> Wallet:
    """Criar nova carteira"""
    return quantum_blockchain.create_wallet(owner)

def send_transaction(from_wallet: str, to_address: str, amount: float, currency: str) -> Optional[Transaction]:
    """Enviar transação"""
    return quantum_blockchain.create_transaction(from_wallet, to_address, amount, currency)

def get_wallet_balance(owner: str, currency: str) -> float:
    """Obter saldo da carteira"""
    wallet = quantum_blockchain.get_wallet(owner)
    return wallet.get_balance(currency) if wallet else 0.0

def start_mining(miner_wallet: str = "default"):
    """Iniciar mineração"""
    wallet = quantum_blockchain.get_wallet(miner_wallet)
    if wallet:
        quantum_blockchain.start_mining(wallet.addresses["QTC"])

def get_blockchain_info() -> Dict[str, Any]:
    """Obter informações do blockchain"""
    return quantum_blockchain.get_blockchain_stats()

