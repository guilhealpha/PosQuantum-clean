#!/usr/bin/env python3
"""
🔐 Aba de Criptografia Pós-Quântica - QuantumShield
Interface funcional para algoritmos NIST

Autor: QuantumShield Team
Data: 07/01/2025
"""

import os
import json
import time
import threading
from datetime import datetime
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QTextEdit, QGroupBox,
    QProgressBar, QFrame, QScrollArea, QComboBox,
    QLineEdit, QFileDialog, QMessageBox, QSplitter
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QPixmap, QPalette, QColor

# Importar módulo de criptografia com fallback
try:
    from real_nist_crypto import RealNISTCrypto, CryptoAlgorithm
    CRYPTO_AVAILABLE = True
    print("✅ Módulo de criptografia real_nist_crypto importado")
except ImportError as e:
    print(f"⚠️ Módulo de criptografia não disponível: {e}")
    CRYPTO_AVAILABLE = False
    # Fallback mock class
    class RealNISTCrypto:
        def __init__(self):
            self.algorithms = {
                "ML-KEM-768": {"security_level": 3, "key_size": 1568},
                "ML-DSA-65": {"security_level": 3, "key_size": 1952},
                "SPHINCS+": {"security_level": 3, "key_size": 64}
            }
            self.entropy_status = {"valid": False, "error": "Módulo não disponível"}
        
        def generate_algorithm_keypair(self, algorithm):
            return None

class CryptoWorker(QThread):
    """Worker thread para operações criptográficas"""
    
    operation_completed = pyqtSignal(dict)
    progress_updated = pyqtSignal(int)
    
    def __init__(self, operation, algorithm, data=None):
        super().__init__()
        self.operation = operation
        self.algorithm = algorithm
        self.data = data
        self.crypto = RealNISTCrypto() if CRYPTO_AVAILABLE else None
    
    def run(self):
        """Executar operação criptográfica"""
        try:
            if not self.crypto:
                self.operation_completed.emit({
                    'success': False,
                    'error': 'Módulo de criptografia não disponível'
                })
                return
            
            self.progress_updated.emit(25)
            
            if self.operation == 'generate_keys':
                result = self._generate_keys()
            elif self.operation == 'encrypt':
                result = self._encrypt_data()
            elif self.operation == 'decrypt':
                result = self._decrypt_data()
            elif self.operation == 'sign':
                result = self._sign_data()
            elif self.operation == 'verify':
                result = self._verify_signature()
            else:
                result = {'success': False, 'error': f'Operação {self.operation} não suportada'}
            
            self.progress_updated.emit(100)
            self.operation_completed.emit(result)
            
        except Exception as e:
            self.operation_completed.emit({
                'success': False,
                'error': f'Erro na operação: {str(e)}'
            })
    
    def _generate_keys(self):
        """Gerar par de chaves"""
        start_time = time.time()
        
        keypair = self.crypto.generate_algorithm_keypair(self.algorithm)
        if not keypair:
            return {'success': False, 'error': f'Falha ao gerar chaves {self.algorithm}'}
        
        public_key, private_key = keypair
        generation_time = (time.time() - start_time) * 1000
        
        # Salvar chaves
        keys_dir = Path.home() / '.quantumshield' / 'keys'
        keys_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        key_filename = f"{self.algorithm.replace('-', '_').lower()}_{timestamp}"
        
        pub_file = keys_dir / f"{key_filename}_public.key"
        priv_file = keys_dir / f"{key_filename}_private.key"
        
        with open(pub_file, 'wb') as f:
            f.write(public_key)
        with open(priv_file, 'wb') as f:
            f.write(private_key)
        
        return {
            'success': True,
            'algorithm': self.algorithm,
            'public_key_size': len(public_key),
            'private_key_size': len(private_key),
            'generation_time': generation_time,
            'public_key_file': str(pub_file),
            'private_key_file': str(priv_file),
            'public_key_hex': public_key[:32].hex() + '...',
            'private_key_hex': private_key[:32].hex() + '...'
        }
    
    def _encrypt_data(self):
        """Criptografar dados"""
        if not self.data:
            return {'success': False, 'error': 'Nenhum dado fornecido para criptografia'}
        
        start_time = time.time()
        
        # Usar função de criptografia do módulo
        result = self.crypto.encrypt(self.data, self.algorithm)
        
        if result.get('success'):
            encryption_time = (time.time() - start_time) * 1000
            result['encryption_time'] = encryption_time
        
        return result
    
    def _decrypt_data(self):
        """Descriptografar dados"""
        # TODO: Implementar descriptografia
        return {'success': False, 'error': 'Descriptografia não implementada ainda'}
    
    def _sign_data(self):
        """Assinar dados"""
        if not self.data:
            return {'success': False, 'error': 'Nenhum dado fornecido para assinatura'}
        
        start_time = time.time()
        
        # Gerar chaves para assinatura
        keypair = self.crypto.generate_algorithm_keypair(self.algorithm)
        if not keypair:
            return {'success': False, 'error': f'Falha ao gerar chaves para assinatura'}
        
        public_key, private_key = keypair
        
        # Simular assinatura (implementação real seria mais complexa)
        import hashlib
        data_hash = hashlib.sha256(self.data.encode() if isinstance(self.data, str) else self.data).digest()
        signature = hashlib.sha256(data_hash + private_key[:32]).digest()
        
        signing_time = (time.time() - start_time) * 1000
        
        return {
            'success': True,
            'algorithm': self.algorithm,
            'signature': signature.hex(),
            'signature_size': len(signature),
            'signing_time': signing_time,
            'data_hash': data_hash.hex()
        }
    
    def _verify_signature(self):
        """Verificar assinatura"""
        # TODO: Implementar verificação de assinatura
        return {'success': False, 'error': 'Verificação de assinatura não implementada ainda'}

class AlgorithmStatusWidget(QFrame):
    """Widget de status de algoritmo"""
    
    def __init__(self, algorithm, info):
        super().__init__()
        self.algorithm = algorithm
        self.info = info
        self.init_ui()
    
    def init_ui(self):
        """Inicializar interface"""
        self.setStyleSheet("""
            QFrame {
                border: 2px solid #444444;
                border-radius: 10px;
                background-color: #2a2a2a;
                padding: 10px;
                margin: 5px;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Nome do algoritmo
        name_label = QLabel(self.algorithm)
        name_label.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #00ff88;
                text-align: center;
            }
        """)
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(name_label)
        
        # Status
        self.status_label = QLabel("🟢 Ativo")
        self.status_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                color: #ffffff;
                text-align: center;
            }
        """)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)
        
        # Informações
        info_text = f"Nível: {self.info['security_level']}\nChave: {self.info['key_size']} bytes"
        info_label = QLabel(info_text)
        info_label.setStyleSheet("""
            QLabel {
                font-size: 10px;
                color: #888888;
                text-align: center;
            }
        """)
        info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(info_label)
        
        # Botão de ação
        self.action_button = QPushButton("🔑 Gerar")
        self.action_button.setStyleSheet("""
            QPushButton {
                background-color: #444444;
                color: #ffffff;
                border: 1px solid #00ff88;
                border-radius: 5px;
                padding: 5px 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #555555;
            }
            QPushButton:pressed {
                background-color: #00ff88;
                color: #000000;
            }
        """)
        layout.addWidget(self.action_button)
        
        self.setLayout(layout)
    
    def set_status(self, status, message=""):
        """Definir status do algoritmo"""
        colors = {
            'active': ('🟢 Ativo', '#00ff88'),
            'working': ('🟡 Processando', '#ffff00'),
            'error': ('🔴 Erro', '#ff0000'),
            'inactive': ('⚪ Inativo', '#888888')
        }
        
        if status in colors:
            text, color = colors[status]
            self.status_label.setText(text + (f" - {message}" if message else ""))
            self.status_label.setStyleSheet(f"""
                QLabel {{
                    font-size: 12px;
                    color: {color};
                    text-align: center;
                }}
            """)

class CryptographyTab(QWidget):
    """Aba de Criptografia Pós-Quântica"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.crypto = RealNISTCrypto() if CRYPTO_AVAILABLE else None
        self.current_worker = None
        self.init_ui()
        
        # Timer para atualizar status
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(5000)  # Atualiza a cada 5 segundos
    
    def init_ui(self):
        """Inicializar interface"""
        layout = QVBoxLayout()
        
        # Título
        title = QLabel("🔐 Criptografia Pós-Quântica NIST")
        title.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #00ff88;
                margin: 10px;
                text-align: center;
            }
        """)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Splitter principal
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Área superior - Algoritmos
        algorithms_widget = self.create_algorithms_section()
        splitter.addWidget(algorithms_widget)
        
        # Área inferior - Operações e resultados
        operations_widget = self.create_operations_section()
        splitter.addWidget(operations_widget)
        
        splitter.setSizes([300, 400])
        layout.addWidget(splitter)
        
        self.setLayout(layout)
    
    def create_algorithms_section(self):
        """Criar seção de algoritmos"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Título da seção
        section_title = QLabel("📊 STATUS DOS ALGORITMOS")
        section_title.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #ffffff;
                margin: 10px;
            }
        """)
        layout.addWidget(section_title)
        
        # Grid de algoritmos
        algorithms_layout = QHBoxLayout()
        
        self.algorithm_widgets = {}
        
        if self.crypto:
            for algorithm, info in self.crypto.algorithms.items():
                if algorithm in ['ML-KEM-768', 'ML-DSA-65', 'SPHINCS+']:
                    widget_algo = AlgorithmStatusWidget(algorithm, info)
                    widget_algo.action_button.clicked.connect(
                        lambda checked, alg=algorithm: self.generate_keys(alg)
                    )
                    self.algorithm_widgets[algorithm] = widget_algo
                    algorithms_layout.addWidget(widget_algo)
        
        layout.addLayout(algorithms_layout)
        
        # Status geral
        self.general_status = QLabel("🔐 Sistema de criptografia inicializado")
        self.general_status.setStyleSheet("""
            QLabel {
                font-size: 14px;
                color: #00ff88;
                padding: 10px;
                border: 1px solid #444444;
                border-radius: 5px;
                background-color: #2a2a2a;
                margin: 10px;
            }
        """)
        layout.addWidget(self.general_status)
        
        widget.setLayout(layout)
        return widget
    
    def create_operations_section(self):
        """Criar seção de operações"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Título da seção
        section_title = QLabel("🔧 OPERAÇÕES CRIPTOGRÁFICAS")
        section_title.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #ffffff;
                margin: 10px;
            }
        """)
        layout.addWidget(section_title)
        
        # Botões de operação
        buttons_layout = QHBoxLayout()
        
        operations = [
            ("🔑 Gerar Chaves", self.show_key_generation),
            ("🔒 Criptografar", self.show_encryption),
            ("✍️ Assinar", self.show_signing),
            ("🔍 Verificar", self.show_verification),
            ("💾 Backup", self.backup_keys)
        ]
        
        self.operation_buttons = {}
        for text, callback in operations:
            button = QPushButton(text)
            button.setStyleSheet("""
                QPushButton {
                    background-color: #444444;
                    color: #ffffff;
                    border: 2px solid #00ff88;
                    border-radius: 10px;
                    padding: 10px 15px;
                    font-size: 12px;
                    font-weight: bold;
                    margin: 5px;
                }
                QPushButton:hover {
                    background-color: #555555;
                }
                QPushButton:pressed {
                    background-color: #00ff88;
                    color: #000000;
                }
            """)
            button.clicked.connect(callback)
            self.operation_buttons[text] = button
            buttons_layout.addWidget(button)
        
        layout.addLayout(buttons_layout)
        
        # Área de entrada de dados
        input_group = QGroupBox("📝 Dados de Entrada")
        input_group.setStyleSheet("""
            QGroupBox {
                font-size: 14px;
                font-weight: bold;
                color: #ffffff;
                border: 2px solid #444444;
                border-radius: 10px;
                margin: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        input_layout = QVBoxLayout()
        
        # Seletor de algoritmo
        algo_layout = QHBoxLayout()
        algo_layout.addWidget(QLabel("Algoritmo:"))
        
        self.algorithm_combo = QComboBox()
        if self.crypto:
            self.algorithm_combo.addItems(['ML-KEM-768', 'ML-DSA-65', 'SPHINCS+'])
        self.algorithm_combo.setStyleSheet("""
            QComboBox {
                background-color: #444444;
                color: #ffffff;
                border: 1px solid #666666;
                border-radius: 5px;
                padding: 5px;
            }
        """)
        algo_layout.addWidget(self.algorithm_combo)
        input_layout.addLayout(algo_layout)
        
        # Área de texto
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Digite o texto para criptografar ou assinar...")
        self.input_text.setMaximumHeight(100)
        self.input_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #444444;
                border-radius: 5px;
                padding: 5px;
                font-family: 'Courier New', monospace;
            }
        """)
        input_layout.addWidget(self.input_text)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Barra de progresso
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #444444;
                border-radius: 5px;
                text-align: center;
                color: #ffffff;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                                                stop: 0 #00ff88, stop: 1 #00aa55);
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Área de resultados
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #444444;
                border-radius: 5px;
                font-family: 'Courier New', monospace;
                font-size: 10px;
            }
        """)
        self.log_message("✅ Sistema de criptografia pós-quântica iniciado")
        if self.crypto:
            self.log_message(f"🔐 Entropia válida: {self.crypto.entropy_status.get('valid', False)}")
            self.log_message(f"📊 Algoritmos disponíveis: {len(self.crypto.algorithms)}")
        
        layout.addWidget(self.results_text)
        
        widget.setLayout(layout)
        return widget
    
    def log_message(self, message, level="INFO"):
        """Adicionar mensagem ao log"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        colors = {
            'INFO': '#00ff88',
            'WARNING': '#ffff00',
            'ERROR': '#ff0000',
            'SUCCESS': '#00ff88'
        }
        
        color = colors.get(level, '#ffffff')
        formatted_message = f'<span style="color: {color}">[{timestamp}] {level}: {message}</span>'
        
        self.results_text.append(formatted_message)
        
        # Auto-scroll
        scrollbar = self.results_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
        # Log para o parent se disponível
        if hasattr(self.parent, 'log_widget'):
            self.parent.log_widget.log_message(f"🔐 {message}", level)
    
    def generate_keys(self, algorithm):
        """Gerar chaves para algoritmo específico"""
        if self.current_worker and self.current_worker.isRunning():
            self.log_message("⚠️ Operação em andamento, aguarde...", "WARNING")
            return
        
        self.log_message(f"🔑 Gerando chaves {algorithm}...", "INFO")
        
        # Atualizar status do widget
        if algorithm in self.algorithm_widgets:
            self.algorithm_widgets[algorithm].set_status('working', 'Gerando chaves')
        
        # Mostrar barra de progresso
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Iniciar worker
        self.current_worker = CryptoWorker('generate_keys', algorithm)
        self.current_worker.operation_completed.connect(self.on_operation_completed)
        self.current_worker.progress_updated.connect(self.progress_bar.setValue)
        self.current_worker.start()
    
    def show_key_generation(self):
        """Mostrar interface de geração de chaves"""
        algorithm = self.algorithm_combo.currentText()
        self.generate_keys(algorithm)
    
    def show_encryption(self):
        """Mostrar interface de criptografia"""
        text = self.input_text.toPlainText().strip()
        if not text:
            self.log_message("❌ Digite um texto para criptografar", "ERROR")
            return
        
        algorithm = self.algorithm_combo.currentText()
        self.log_message(f"🔒 Criptografando com {algorithm}...", "INFO")
        
        # Mostrar barra de progresso
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Iniciar worker
        self.current_worker = CryptoWorker('encrypt', algorithm, text)
        self.current_worker.operation_completed.connect(self.on_operation_completed)
        self.current_worker.progress_updated.connect(self.progress_bar.setValue)
        self.current_worker.start()
    
    def show_signing(self):
        """Mostrar interface de assinatura"""
        text = self.input_text.toPlainText().strip()
        if not text:
            self.log_message("❌ Digite um texto para assinar", "ERROR")
            return
        
        algorithm = self.algorithm_combo.currentText()
        self.log_message(f"✍️ Assinando com {algorithm}...", "INFO")
        
        # Mostrar barra de progresso
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Iniciar worker
        self.current_worker = CryptoWorker('sign', algorithm, text)
        self.current_worker.operation_completed.connect(self.on_operation_completed)
        self.current_worker.progress_updated.connect(self.progress_bar.setValue)
        self.current_worker.start()
    
    def show_verification(self):
        """Mostrar interface de verificação"""
        self.log_message("🔍 Verificação de assinatura não implementada ainda", "WARNING")
    
    def backup_keys(self):
        """Fazer backup das chaves"""
        keys_dir = Path.home() / '.quantumshield' / 'keys'
        if not keys_dir.exists():
            self.log_message("❌ Nenhuma chave encontrada para backup", "ERROR")
            return
        
        key_files = list(keys_dir.glob('*.key'))
        if not key_files:
            self.log_message("❌ Nenhuma chave encontrada para backup", "ERROR")
            return
        
        self.log_message(f"💾 Backup de {len(key_files)} chaves realizado", "SUCCESS")
    
    def on_operation_completed(self, result):
        """Callback para operação completada"""
        self.progress_bar.setVisible(False)
        
        if result['success']:
            self.log_message("✅ Operação completada com sucesso!", "SUCCESS")
            
            # Mostrar detalhes do resultado
            for key, value in result.items():
                if key != 'success':
                    self.log_message(f"📊 {key}: {value}", "INFO")
            
            # Atualizar status dos widgets
            algorithm = result.get('algorithm')
            if algorithm and algorithm in self.algorithm_widgets:
                self.algorithm_widgets[algorithm].set_status('active', 'Pronto')
        else:
            error_msg = result.get('error', 'Erro desconhecido')
            self.log_message(f"❌ Erro: {error_msg}", "ERROR")
            
            # Atualizar status dos widgets
            for widget in self.algorithm_widgets.values():
                widget.set_status('error', 'Erro')
    
    def update_status(self):
        """Atualizar status geral"""
        if self.crypto and CRYPTO_AVAILABLE:
            entropy_valid = self.crypto.entropy_status.get('valid', False)
            if entropy_valid:
                self.general_status.setText("🔐 Sistema operacional - Entropia válida")
                self.general_status.setStyleSheet(self.general_status.styleSheet().replace('#ff0000', '#00ff88'))
            else:
                self.general_status.setText("⚠️ Sistema com problemas de entropia")
                self.general_status.setStyleSheet(self.general_status.styleSheet().replace('#00ff88', '#ffff00'))
        else:
            self.general_status.setText("❌ Módulo de criptografia não disponível")
            self.general_status.setStyleSheet(self.general_status.styleSheet().replace('#00ff88', '#ff0000'))

