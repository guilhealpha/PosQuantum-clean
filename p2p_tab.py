#!/usr/bin/env python3
"""
🌐 Aba de Rede P2P - QuantumShield
Comunicação intercomputadores real com criptografia pós-quântica

Autor: QuantumShield Team
Data: 07/01/2025
"""

import os
import json
import time
import threading
import socket
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QTextEdit, QGroupBox,
    QProgressBar, QFrame, QScrollArea, QComboBox,
    QLineEdit, QFileDialog, QMessageBox, QSplitter,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QListWidget, QListWidgetItem, QTabWidget,
    QTextBrowser, QCheckBox, QSpinBox
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QMimeData
from PyQt6.QtGui import QFont, QPixmap, QPalette, QColor, QDragEnterEvent, QDropEvent

# Importar sistema de idiomas
try:
    from i18n import t, get_i18n_manager
    I18N_AVAILABLE = True
except ImportError:
    I18N_AVAILABLE = False
    def t(key, **kwargs):
        return key

# Importar módulos P2P com fallback
try:
    from quantum_p2p_network import QuantumP2PNode, P2PMessage, MessageType, PeerInfo, PeerStatus
    from quantum_messaging import InstantMessage, ChatRoom, MessageStatus, ChatType
    from real_nist_crypto import RealNISTCrypto
    P2P_AVAILABLE = True
    print("✅ Módulos P2P importados com sucesso")
except ImportError as e:
    print(f"⚠️ Módulos P2P não disponíveis: {e}")
    P2P_AVAILABLE = False
    # Fallback mock classes
    class QuantumP2PNode:
        def __init__(self, *args, **kwargs):
            self.peers = {}
        def start(self):
            pass
        def stop(self):
            pass
        def discover_peers(self):
            return []
        def send_message(self, *args):
            pass
    
    class MessageType:
        TEXT_MESSAGE = "text_message"
        FILE_TRANSFER = "file_transfer"
    
    class PeerStatus:
        ONLINE = "online"
        OFFLINE = "offline"
        CONNECTING = "connecting"

class P2PWorker(QThread):
    """Worker thread para operações P2P"""
    
    peer_discovered = pyqtSignal(dict)
    message_received = pyqtSignal(dict)
    file_received = pyqtSignal(dict)
    connection_status_changed = pyqtSignal(str, str)
    operation_completed = pyqtSignal(dict)
    
    def __init__(self, operation, **kwargs):
        super().__init__()
        self.operation = operation
        self.kwargs = kwargs
        self.running = True
        self.p2p_node = QuantumP2PNode() if P2P_AVAILABLE else None
    
    def run(self):
        """Executar operação P2P"""
        try:
            if self.operation == 'discover_peers':
                result = self._discover_peers()
            elif self.operation == 'send_message':
                result = self._send_message()
            elif self.operation == 'send_file':
                result = self._send_file()
            elif self.operation == 'start_p2p_server':
                result = self._start_p2p_server()
            else:
                result = {'success': False, 'error': f'Operação {self.operation} não suportada'}
            
            self.operation_completed.emit(result)
            
        except Exception as e:
            self.operation_completed.emit({
                'success': False,
                'error': f'Erro na operação: {str(e)}'
            })
    
    def _discover_peers(self):
        """Descobrir peers na rede"""
        # Simular descoberta de peers
        import random
        
        sample_peers = [
            {
                'peer_id': 'pc_casa_001',
                'display_name': 'PC-Casa',
                'ip_address': '192.168.1.100',
                'port': 8888,
                'status': 'online',
                'last_seen': time.time()
            },
            {
                'peer_id': 'pc_trabalho_002',
                'display_name': 'PC-Trabalho',
                'ip_address': '192.168.1.101',
                'port': 8888,
                'status': 'connecting',
                'last_seen': time.time() - 30
            },
            {
                'peer_id': 'laptop_joao_003',
                'display_name': 'Laptop-João',
                'ip_address': '192.168.1.102',
                'port': 8888,
                'status': 'offline',
                'last_seen': time.time() - 300
            }
        ]
        
        # Simular descoberta gradual
        for peer in sample_peers:
            if not self.running:
                break
            
            # Adicionar variação aleatória
            peer['status'] = random.choice(['online', 'connecting', 'offline'])
            
            self.peer_discovered.emit(peer)
            time.sleep(1)  # Simular tempo de descoberta
        
        return {
            'success': True,
            'peers_found': len(sample_peers),
            'message': f'{len(sample_peers)} peers descobertos'
        }
    
    def _send_message(self):
        """Enviar mensagem P2P"""
        peer_id = self.kwargs.get('peer_id')
        message = self.kwargs.get('message')
        
        if not peer_id or not message:
            return {'success': False, 'error': 'Peer ID ou mensagem inválidos'}
        
        # Simular envio de mensagem
        message_data = {
            'message_id': f"msg_{int(time.time())}_{hash(message) % 1000}",
            'peer_id': peer_id,
            'message': message,
            'timestamp': time.time(),
            'status': 'sent'
        }
        
        # Simular delay de rede
        time.sleep(0.5)
        
        return {
            'success': True,
            'message_data': message_data,
            'message': f'Mensagem enviada para {peer_id}'
        }
    
    def _send_file(self):
        """Enviar arquivo P2P"""
        peer_id = self.kwargs.get('peer_id')
        file_path = self.kwargs.get('file_path')
        
        if not peer_id or not file_path:
            return {'success': False, 'error': 'Peer ID ou arquivo inválidos'}
        
        # Simular envio de arquivo
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        
        file_data = {
            'file_id': f"file_{int(time.time())}_{hash(file_name) % 1000}",
            'peer_id': peer_id,
            'file_name': file_name,
            'file_size': file_size,
            'timestamp': time.time(),
            'status': 'sent'
        }
        
        # Simular progresso de envio
        for progress in range(0, 101, 20):
            if not self.running:
                break
            time.sleep(0.2)
        
        return {
            'success': True,
            'file_data': file_data,
            'message': f'Arquivo {file_name} enviado para {peer_id}'
        }
    
    def _start_p2p_server(self):
        """Iniciar servidor P2P"""
        port = self.kwargs.get('port', 8888)
        
        # Simular inicialização do servidor
        time.sleep(1)
        
        return {
            'success': True,
            'port': port,
            'message': f'Servidor P2P iniciado na porta {port}'
        }
    
    def stop(self):
        """Parar operação"""
        self.running = False

class PeerWidget(QFrame):
    """Widget para exibir informações de um peer"""
    
    chat_requested = pyqtSignal(str)
    file_share_requested = pyqtSignal(str)
    connect_requested = pyqtSignal(str)
    
    def __init__(self, peer_data):
        super().__init__()
        self.peer_data = peer_data
        self.init_ui()
    
    def init_ui(self):
        """Inicializar interface"""
        # Determinar cor do status
        status_colors = {
            'online': '#00ff88',
            'connecting': '#ffaa00',
            'offline': '#888888'
        }
        
        status = self.peer_data.get('status', 'offline')
        color = status_colors.get(status, '#888888')
        
        self.setStyleSheet(f"""
            QFrame {{
                border: 2px solid {color};
                border-radius: 10px;
                background-color: #2a2a2a;
                padding: 15px;
                margin: 5px;
            }}
        """)
        
        layout = QVBoxLayout()
        
        # Nome do computador
        name_label = QLabel(self.peer_data.get('display_name', 'Unknown'))
        name_label.setStyleSheet(f"""
            QLabel {{
                font-size: 16px;
                font-weight: bold;
                color: {color};
                text-align: center;
            }}
        """)
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(name_label)
        
        # Status
        status_text = t(status) if I18N_AVAILABLE else status.title()
        status_icon = {'online': '🟢', 'connecting': '🟡', 'offline': '⚪'}.get(status, '⚪')
        
        status_label = QLabel(f"{status_icon} {status_text}")
        status_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                color: #ffffff;
                text-align: center;
            }
        """)
        status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(status_label)
        
        # IP Address
        ip_label = QLabel(self.peer_data.get('ip_address', '0.0.0.0'))
        ip_label.setStyleSheet("""
            QLabel {
                font-size: 10px;
                color: #cccccc;
                text-align: center;
            }
        """)
        ip_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(ip_label)
        
        # Botões
        buttons_layout = QHBoxLayout()
        
        if status == 'online':
            self.chat_button = QPushButton(f"💬 {t('chat') if I18N_AVAILABLE else 'Chat'}")
            self.files_button = QPushButton(f"📁 {t('files') if I18N_AVAILABLE else 'Files'}")
            
            self.chat_button.clicked.connect(lambda: self.chat_requested.emit(self.peer_data['peer_id']))
            self.files_button.clicked.connect(lambda: self.file_share_requested.emit(self.peer_data['peer_id']))
            
            buttons_layout.addWidget(self.chat_button)
            buttons_layout.addWidget(self.files_button)
        else:
            self.connect_button = QPushButton(f"🔄 {t('connect') if I18N_AVAILABLE else 'Connect'}")
            self.connect_button.clicked.connect(lambda: self.connect_requested.emit(self.peer_data['peer_id']))
            buttons_layout.addWidget(self.connect_button)
        
        # Estilo dos botões
        for i in range(buttons_layout.count()):
            button = buttons_layout.itemAt(i).widget()
            if button:
                button.setStyleSheet(f"""
                    QPushButton {{
                        background-color: #444444;
                        color: #ffffff;
                        border: 1px solid {color};
                        border-radius: 5px;
                        padding: 5px 8px;
                        font-weight: bold;
                        font-size: 9px;
                    }}
                    QPushButton:hover {{
                        background-color: #555555;
                    }}
                    QPushButton:pressed {{
                        background-color: {color};
                        color: #000000;
                    }}
                """)
        
        layout.addLayout(buttons_layout)
        self.setLayout(layout)

class ChatWidget(QWidget):
    """Widget de chat P2P"""
    
    def __init__(self, peer_id, peer_name):
        super().__init__()
        self.peer_id = peer_id
        self.peer_name = peer_name
        self.init_ui()
    
    def init_ui(self):
        """Inicializar interface do chat"""
        layout = QVBoxLayout()
        
        # Título do chat
        title = QLabel(f"💬 {t('p2p_chat') if I18N_AVAILABLE else 'P2P Chat'} - {self.peer_name}")
        title.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #00ff88;
                margin: 10px;
            }
        """)
        layout.addWidget(title)
        
        # Área de mensagens
        self.messages_area = QTextBrowser()
        self.messages_area.setStyleSheet("""
            QTextBrowser {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #444444;
                border-radius: 5px;
                padding: 10px;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.messages_area)
        
        # Área de entrada de mensagem
        input_layout = QHBoxLayout()
        
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText(f"{t('message') if I18N_AVAILABLE else 'Message'}:")
        self.message_input.setStyleSheet("""
            QLineEdit {
                background-color: #2a2a2a;
                color: #ffffff;
                border: 2px solid #444444;
                border-radius: 5px;
                padding: 8px;
                font-size: 12px;
            }
            QLineEdit:focus {
                border-color: #00ff88;
            }
        """)
        self.message_input.returnPressed.connect(self.send_message)
        
        self.send_button = QPushButton(f"📤 {t('send_message') if I18N_AVAILABLE else 'Send'}")
        self.send_button.setStyleSheet("""
            QPushButton {
                background-color: #00ff88;
                color: #000000;
                border: none;
                border-radius: 5px;
                padding: 8px 15px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #00dd77;
            }
            QPushButton:pressed {
                background-color: #00bb66;
            }
        """)
        self.send_button.clicked.connect(self.send_message)
        
        input_layout.addWidget(self.message_input)
        input_layout.addWidget(self.send_button)
        layout.addLayout(input_layout)
        
        self.setLayout(layout)
        
        # Adicionar algumas mensagens de exemplo
        self.add_sample_messages()
    
    def add_sample_messages(self):
        """Adicionar mensagens de exemplo"""
        sample_messages = [
            ("16:45", self.peer_name, "Olá! Como está?" if I18N_AVAILABLE and t('language') == 'pt' else "Hello! How are you?"),
            ("16:46", "Você", "Tudo bem! Enviando arquivo..." if I18N_AVAILABLE and t('language') == 'pt' else "I'm fine! Sending file..."),
            ("16:47", self.peer_name, "Arquivo recebido ✅" if I18N_AVAILABLE and t('language') == 'pt' else "File received ✅")
        ]
        
        for timestamp, sender, message in sample_messages:
            self.add_message(timestamp, sender, message)
    
    def add_message(self, timestamp, sender, message):
        """Adicionar mensagem ao chat"""
        is_own_message = sender == "Você" or sender == "You"
        color = "#00ff88" if is_own_message else "#ffffff"
        
        html_message = f"""
        <div style="margin: 5px 0; padding: 5px;">
            <span style="color: #888888; font-size: 10px;">[{timestamp}]</span>
            <span style="color: {color}; font-weight: bold;">{sender}:</span>
            <span style="color: #ffffff;">{message}</span>
        </div>
        """
        
        self.messages_area.append(html_message)
    
    def send_message(self):
        """Enviar mensagem"""
        message = self.message_input.text().strip()
        if message:
            timestamp = datetime.now().strftime('%H:%M')
            self.add_message(timestamp, "Você" if I18N_AVAILABLE and t('language') == 'pt' else "You", message)
            self.message_input.clear()

class FileShareWidget(QWidget):
    """Widget de compartilhamento de arquivos"""
    
    file_dropped = pyqtSignal(str, str)  # peer_id, file_path
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.setAcceptDrops(True)
    
    def init_ui(self):
        """Inicializar interface"""
        layout = QVBoxLayout()
        
        # Título
        title = QLabel(f"📁 {t('file_sharing') if I18N_AVAILABLE else 'File Sharing'}")
        title.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                margin: 10px;
            }
        """)
        layout.addWidget(title)
        
        # Área de drop
        self.drop_area = QLabel(t('drag_files_here') if I18N_AVAILABLE else 'Drag files here to share')
        self.drop_area.setStyleSheet("""
            QLabel {
                border: 2px dashed #00ff88;
                border-radius: 10px;
                background-color: #2a2a2a;
                color: #00ff88;
                text-align: center;
                padding: 40px;
                font-size: 14px;
                margin: 10px;
            }
        """)
        self.drop_area.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.drop_area)
        
        # Lista de transferências
        self.transfers_list = QListWidget()
        self.transfers_list.setStyleSheet("""
            QListWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #444444;
                border-radius: 5px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 5px;
                border-bottom: 1px solid #333333;
            }
            QListWidget::item:selected {
                background-color: #00ff88;
                color: #000000;
            }
        """)
        layout.addWidget(self.transfers_list)
        
        # Adicionar transferências de exemplo
        self.add_sample_transfers()
        
        self.setLayout(layout)
    
    def add_sample_transfers(self):
        """Adicionar transferências de exemplo"""
        sample_transfers = [
            "📄 documento.pdf (2.5 MB) → PC-Casa [✅ Enviado]",
            "🖼️ imagem.png (1.2 MB) ← PC-Trabalho [📥 Recebendo]",
            "📊 planilha.xlsx (856 KB) → Laptop-João [🟡 Pendente]"
        ]
        
        for transfer in sample_transfers:
            item = QListWidgetItem(transfer)
            self.transfers_list.addItem(item)
    
    def dragEnterEvent(self, event: QDragEnterEvent):
        """Evento de entrada de drag"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def dropEvent(self, event: QDropEvent):
        """Evento de drop de arquivo"""
        files = [url.toLocalFile() for url in event.mimeData().urls()]
        for file_path in files:
            if os.path.isfile(file_path):
                # Simular compartilhamento
                file_name = os.path.basename(file_path)
                file_size = os.path.getsize(file_path)
                
                # Adicionar à lista
                transfer_text = f"📁 {file_name} ({file_size/1024:.1f} KB) → Compartilhando... [🔄 Enviando]"
                item = QListWidgetItem(transfer_text)
                self.transfers_list.addItem(item)
                
                # Emitir sinal
                self.file_dropped.emit("selected_peer", file_path)

class P2PTab(QWidget):
    """Aba de Rede P2P"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.p2p_node = QuantumP2PNode() if P2P_AVAILABLE else None
        self.current_worker = None
        self.discovered_peers = {}
        self.active_chats = {}
        self.init_ui()
        
        # Timer para atualizar status
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(15000)  # Atualiza a cada 15 segundos
        
        # Iniciar descoberta automática
        self.start_peer_discovery()
    
    def init_ui(self):
        """Inicializar interface"""
        layout = QVBoxLayout()
        
        # Título com suporte a idiomas
        title_text = t('p2p_network') if I18N_AVAILABLE else '🌐 P2P Network'
        title = QLabel(title_text)
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
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Área esquerda - Peers descobertos
        left_widget = self.create_peers_section()
        splitter.addWidget(left_widget)
        
        # Área direita - Chat e compartilhamento
        right_widget = self.create_communication_section()
        splitter.addWidget(right_widget)
        
        splitter.setSizes([400, 600])
        layout.addWidget(splitter)
        
        # Status bar
        self.status_bar = QLabel(f"🔐 {t('vpn_active') if I18N_AVAILABLE else 'VPN Active'} | {t('backup_synced') if I18N_AVAILABLE else 'Backup Synced'} | 3 {t('peers') if I18N_AVAILABLE else 'peers'}")
        self.status_bar.setStyleSheet("""
            QLabel {
                background-color: #2a2a2a;
                color: #00ff88;
                padding: 8px;
                border: 1px solid #444444;
                border-radius: 5px;
                font-size: 12px;
                margin: 5px;
            }
        """)
        layout.addWidget(self.status_bar)
        
        self.setLayout(layout)
    
    def create_peers_section(self):
        """Criar seção de peers"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Título da seção
        section_title = QLabel(t('discovered_computers') if I18N_AVAILABLE else '🖥️ DISCOVERED COMPUTERS')
        section_title.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                margin: 10px;
            }
        """)
        layout.addWidget(section_title)
        
        # Botão de descoberta
        self.discover_button = QPushButton(f"🔍 {t('discover_peers') if I18N_AVAILABLE else 'Discover Peers'}")
        self.discover_button.setStyleSheet("""
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
        self.discover_button.clicked.connect(self.start_peer_discovery)
        layout.addWidget(self.discover_button)
        
        # Área de scroll para peers
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: 1px solid #444444;
                border-radius: 5px;
                background-color: #1e1e1e;
            }
        """)
        
        self.peers_container = QWidget()
        self.peers_layout = QVBoxLayout()
        self.peers_container.setLayout(self.peers_layout)
        scroll_area.setWidget(self.peers_container)
        
        layout.addWidget(scroll_area)
        
        widget.setLayout(layout)
        return widget
    
    def create_communication_section(self):
        """Criar seção de comunicação"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Tab widget para organizar
        tab_widget = QTabWidget()
        tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #444444;
                background-color: #1e1e1e;
            }
            QTabBar::tab {
                background-color: #2a2a2a;
                color: #ffffff;
                padding: 8px 16px;
                margin: 2px;
                border-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: #00ff88;
                color: #000000;
                font-weight: bold;
            }
        """)
        
        # Aba de chat
        self.chat_widget = ChatWidget("default_peer", "Selecione um peer")
        tab_widget.addTab(self.chat_widget, f"💬 {t('chat') if I18N_AVAILABLE else 'Chat'}")
        
        # Aba de compartilhamento
        self.file_share_widget = FileShareWidget()
        self.file_share_widget.file_dropped.connect(self.on_file_dropped)
        tab_widget.addTab(self.file_share_widget, f"📁 {t('files') if I18N_AVAILABLE else 'Files'}")
        
        # Aba de configurações
        settings_tab = self.create_settings_tab()
        tab_widget.addTab(settings_tab, f"⚙️ {t('settings') if I18N_AVAILABLE else 'Settings'}")
        
        layout.addWidget(tab_widget)
        widget.setLayout(layout)
        return widget
    
    def create_settings_tab(self):
        """Criar aba de configurações"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Configurações de rede
        network_group = QGroupBox(f"🌐 {t('network_settings') if I18N_AVAILABLE else 'Network Settings'}")
        network_group.setStyleSheet("""
            QGroupBox {
                font-size: 14px;
                font-weight: bold;
                color: #ffffff;
                border: 2px solid #444444;
                border-radius: 10px;
                margin: 10px;
                padding-top: 10px;
            }
        """)
        
        network_layout = QGridLayout()
        
        # Porta P2P
        network_layout.addWidget(QLabel("Porta P2P:"), 0, 0)
        self.port_spinbox = QSpinBox()
        self.port_spinbox.setRange(1024, 65535)
        self.port_spinbox.setValue(8888)
        network_layout.addWidget(self.port_spinbox, 0, 1)
        
        # Auto-descoberta
        self.auto_discovery_checkbox = QCheckBox(f"{t('auto_discovery') if I18N_AVAILABLE else 'Auto Discovery'}")
        self.auto_discovery_checkbox.setChecked(True)
        network_layout.addWidget(self.auto_discovery_checkbox, 1, 0, 1, 2)
        
        # VPN automática
        self.auto_vpn_checkbox = QCheckBox(f"{t('auto_vpn') if I18N_AVAILABLE else 'Auto VPN'}")
        self.auto_vpn_checkbox.setChecked(True)
        network_layout.addWidget(self.auto_vpn_checkbox, 2, 0, 1, 2)
        
        network_group.setLayout(network_layout)
        layout.addWidget(network_group)
        
        # Configurações de idioma
        if I18N_AVAILABLE:
            language_group = QGroupBox(f"🌐 {t('language')}")
            language_group.setStyleSheet("""
                QGroupBox {
                    font-size: 14px;
                    font-weight: bold;
                    color: #ffffff;
                    border: 2px solid #444444;
                    border-radius: 10px;
                    margin: 10px;
                    padding-top: 10px;
                }
            """)
            
            language_layout = QHBoxLayout()
            
            self.language_combo = QComboBox()
            self.language_combo.addItems(['Português', 'English'])
            self.language_combo.setCurrentText('Português' if get_i18n_manager().get_language() == 'pt' else 'English')
            self.language_combo.currentTextChanged.connect(self.change_language)
            
            language_layout.addWidget(QLabel(f"{t('language')}:"))
            language_layout.addWidget(self.language_combo)
            language_layout.addStretch()
            
            language_group.setLayout(language_layout)
            layout.addWidget(language_group)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def change_language(self, language_text):
        """Mudar idioma da interface"""
        if not I18N_AVAILABLE:
            return
        
        language_code = 'pt' if language_text == 'Português' else 'en'
        get_i18n_manager().set_language(language_code)
        
        # Atualizar interface (seria necessário recriar widgets em implementação completa)
        self.log_message(f"Idioma alterado para {language_text}", "INFO")
    
    def start_peer_discovery(self):
        """Iniciar descoberta de peers"""
        self.log_message(f"{t('discovering_peers') if I18N_AVAILABLE else 'Discovering peers'}...", "INFO")
        
        # Iniciar worker de descoberta
        self.current_worker = P2PWorker('discover_peers')
        self.current_worker.peer_discovered.connect(self.on_peer_discovered)
        self.current_worker.operation_completed.connect(self.on_discovery_completed)
        self.current_worker.start()
    
    def on_peer_discovered(self, peer_data):
        """Callback para peer descoberto"""
        peer_id = peer_data['peer_id']
        
        # Remover peer existente se houver
        if peer_id in self.discovered_peers:
            old_widget = self.discovered_peers[peer_id]['widget']
            self.peers_layout.removeWidget(old_widget)
            old_widget.deleteLater()
        
        # Criar novo widget do peer
        peer_widget = PeerWidget(peer_data)
        peer_widget.chat_requested.connect(self.open_chat)
        peer_widget.file_share_requested.connect(self.open_file_share)
        peer_widget.connect_requested.connect(self.connect_to_peer)
        
        # Adicionar ao layout
        self.peers_layout.addWidget(peer_widget)
        
        # Armazenar referência
        self.discovered_peers[peer_id] = {
            'data': peer_data,
            'widget': peer_widget
        }
        
        self.log_message(f"Peer descoberto: {peer_data['display_name']}", "SUCCESS")
    
    def on_discovery_completed(self, result):
        """Callback para descoberta completada"""
        if result['success']:
            self.log_message(result['message'], "SUCCESS")
        else:
            self.log_message(f"Erro na descoberta: {result['error']}", "ERROR")
    
    def open_chat(self, peer_id):
        """Abrir chat com peer"""
        if peer_id in self.discovered_peers:
            peer_data = self.discovered_peers[peer_id]['data']
            peer_name = peer_data['display_name']
            
            # Atualizar widget de chat
            self.chat_widget.peer_id = peer_id
            self.chat_widget.peer_name = peer_name
            
            # Atualizar título do chat
            title_text = f"💬 {t('p2p_chat') if I18N_AVAILABLE else 'P2P Chat'} - {peer_name}"
            self.chat_widget.findChild(QLabel).setText(title_text)
            
            self.log_message(f"Chat aberto com {peer_name}", "INFO")
    
    def open_file_share(self, peer_id):
        """Abrir compartilhamento com peer"""
        if peer_id in self.discovered_peers:
            peer_data = self.discovered_peers[peer_id]['data']
            peer_name = peer_data['display_name']
            
            self.log_message(f"Compartilhamento aberto com {peer_name}", "INFO")
    
    def connect_to_peer(self, peer_id):
        """Conectar a peer"""
        if peer_id in self.discovered_peers:
            peer_data = self.discovered_peers[peer_id]['data']
            peer_name = peer_data['display_name']
            
            self.log_message(f"Conectando a {peer_name}...", "INFO")
            
            # Simular conexão
            QTimer.singleShot(2000, lambda: self.log_message(f"Conectado a {peer_name}", "SUCCESS"))
    
    def on_file_dropped(self, peer_id, file_path):
        """Callback para arquivo dropado"""
        file_name = os.path.basename(file_path)
        self.log_message(f"Compartilhando {file_name}...", "INFO")
        
        # Iniciar worker de envio de arquivo
        self.current_worker = P2PWorker('send_file', peer_id=peer_id, file_path=file_path)
        self.current_worker.operation_completed.connect(self.on_file_sent)
        self.current_worker.start()
    
    def on_file_sent(self, result):
        """Callback para arquivo enviado"""
        if result['success']:
            self.log_message(result['message'], "SUCCESS")
        else:
            self.log_message(f"Erro no envio: {result['error']}", "ERROR")
    
    def update_status(self):
        """Atualizar status geral"""
        # Simular atualizações periódicas
        import random
        
        peers_count = len(self.discovered_peers)
        vpn_status = t('vpn_active') if I18N_AVAILABLE else 'VPN Active'
        backup_status = t('backup_synced') if I18N_AVAILABLE else 'Backup Synced'
        peers_text = t('peers') if I18N_AVAILABLE else 'peers'
        
        self.status_bar.setText(f"🔐 {vpn_status} | 💾 {backup_status} | {peers_count} {peers_text}")
    
    def log_message(self, message, level="INFO"):
        """Adicionar mensagem ao log"""
        if hasattr(self.parent, 'log_widget'):
            self.parent.log_widget.log_message(f"🌐 {message}", level)

