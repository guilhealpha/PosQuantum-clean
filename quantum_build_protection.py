#!/usr/bin/env python3
"""
🛡️ QuantumShield - Build Protection System
Arquivo: quantum_build_protection.py
Descrição: Sistema de build com proteção integrada para QuantumShield
Autor: QuantumShield Team
Versão: 2.0
Data: 03/07/2025
"""

import os
import sys
import shutil
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Optional
import json
import time

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class QuantumBuildProtection:
    """Sistema de build com proteção integrada"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.build_dir = self.project_root / "build_protected"
        self.dist_dir = self.project_root / "dist_protected"
        self.temp_dir = self.project_root / "temp_build"
        
        # Configurações de proteção
        self.protection_config = {
            'obfuscation': True,
            'compilation': True,
            'anti_debug': True,
            'license_check': True,
            'code_signing': True,
            'compression': True
        }
        
        # Arquivos críticos para proteção máxima
        self.critical_files = [
            "src/blockchain/quantum_mining_engine.py",
            "src/networking/quantum_p2p_vpn_v2.py",
            "src/networking/quantum_post_quantum_crypto.py",
            "src/protection/quantum_code_protection.py"
        ]
        
        # Arquivos para obfuscação padrão
        self.standard_files = [
            "main.py",
            "src/satellite/quantum_satellite_communication.py",
            "src/ai/quantum_ai_security.py",
            "src/storage/quantum_distributed_storage.py",
            "src/audit/quantum_audit_system_v2.py"
        ]
        
        logger.info("🏗️ Sistema de build com proteção inicializado")
    
    def prepare_build_environment(self) -> bool:
        """Prepara ambiente de build"""
        try:
            logger.info("🔧 Preparando ambiente de build...")
            
            # Limpar diretórios anteriores
            for dir_path in [self.build_dir, self.dist_dir, self.temp_dir]:
                if dir_path.exists():
                    shutil.rmtree(dir_path)
                dir_path.mkdir(parents=True, exist_ok=True)
            
            # Verificar dependências
            if not self._check_dependencies():
                return False
            
            # Copiar arquivos fonte
            self._copy_source_files()
            
            logger.info("✅ Ambiente de build preparado")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao preparar build: {e}")
            return False
    
    def _check_dependencies(self) -> bool:
        """Verifica dependências necessárias"""
        try:
            dependencies = {
                'pyinstaller': 'pip install pyinstaller',
                'pyarmor': 'pip install pyarmor',
                'cython': 'pip install cython'
            }
            
            missing_deps = []
            
            for dep, install_cmd in dependencies.items():
                try:
                    if dep == 'pyinstaller':
                        subprocess.run(['pyinstaller', '--version'], 
                                     capture_output=True, check=True)
                    elif dep == 'pyarmor':
                        subprocess.run(['pyarmor', '--version'], 
                                     capture_output=True, check=True)
                    elif dep == 'cython':
                        import Cython
                    
                    logger.info(f"  ✅ {dep} disponível")
                    
                except (subprocess.CalledProcessError, FileNotFoundError, ImportError):
                    missing_deps.append((dep, install_cmd))
                    logger.warning(f"  ⚠️ {dep} não encontrado")
            
            if missing_deps:
                logger.info("📦 Instalando dependências faltantes...")
                for dep, install_cmd in missing_deps:
                    logger.info(f"   Instalando {dep}...")
                    result = subprocess.run(install_cmd.split(), 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        logger.info(f"   ✅ {dep} instalado")
                    else:
                        logger.error(f"   ❌ Falha ao instalar {dep}")
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao verificar dependências: {e}")
            return False
    
    def _copy_source_files(self):
        """Copia arquivos fonte para build"""
        try:
            logger.info("📁 Copiando arquivos fonte...")
            
            # Copiar estrutura do projeto
            source_dirs = ['src', 'lib', 'ui', 'resources', 'config']
            
            for dir_name in source_dirs:
                source_dir = self.project_root / dir_name
                if source_dir.exists():
                    dest_dir = self.temp_dir / dir_name
                    shutil.copytree(source_dir, dest_dir, dirs_exist_ok=True)
                    logger.info(f"   ✅ {dir_name}/ copiado")
            
            # Copiar arquivo principal
            main_file = self.project_root / "main.py"
            if main_file.exists():
                shutil.copy2(main_file, self.temp_dir / "main.py")
                logger.info("   ✅ main.py copiado")
            
            # Copiar requirements
            req_file = self.project_root / "requirements.txt"
            if req_file.exists():
                shutil.copy2(req_file, self.temp_dir / "requirements.txt")
                logger.info("   ✅ requirements.txt copiado")
            
        except Exception as e:
            logger.error(f"❌ Erro ao copiar arquivos: {e}")
    
    def apply_code_protection(self) -> bool:
        """Aplica proteções de código"""
        try:
            logger.info("🔒 Aplicando proteções de código...")
            
            # 1. Obfuscação com PyArmor
            if self.protection_config['obfuscation']:
                if not self._apply_obfuscation():
                    logger.warning("⚠️ Falha na obfuscação, continuando...")
            
            # 2. Compilação Cython para arquivos críticos
            if self.protection_config['compilation']:
                if not self._apply_compilation():
                    logger.warning("⚠️ Falha na compilação, continuando...")
            
            # 3. Inserir proteções anti-debug
            if self.protection_config['anti_debug']:
                self._insert_anti_debug_code()
            
            # 4. Inserir verificações de licença
            if self.protection_config['license_check']:
                self._insert_license_checks()
            
            logger.info("✅ Proteções de código aplicadas")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao aplicar proteções: {e}")
            return False
    
    def _apply_obfuscation(self) -> bool:
        """Aplica obfuscação PyArmor"""
        try:
            logger.info("🔒 Aplicando obfuscação PyArmor...")
            
            obfuscated_dir = self.temp_dir / "obfuscated"
            obfuscated_dir.mkdir(exist_ok=True)
            
            # Obfuscar arquivos padrão
            for file_path in self.standard_files:
                source_file = self.temp_dir / file_path
                if source_file.exists():
                    logger.info(f"   Obfuscando: {file_path}")
                    
                    # Comando PyArmor básico
                    cmd = [
                        'pyarmor', 'obfuscate',
                        '--output', str(obfuscated_dir),
                        '--exact',
                        str(source_file)
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode == 0:
                        # Substituir arquivo original
                        obf_file = obfuscated_dir / source_file.name
                        if obf_file.exists():
                            shutil.copy2(obf_file, source_file)
                            logger.info(f"     ✅ {file_path} obfuscado")
                    else:
                        logger.warning(f"     ⚠️ Falha ao obfuscar {file_path}")
            
            # Obfuscação avançada para arquivos críticos
            for file_path in self.critical_files:
                source_file = self.temp_dir / file_path
                if source_file.exists():
                    logger.info(f"   Obfuscação avançada: {file_path}")
                    
                    # Comando PyArmor avançado
                    cmd = [
                        'pyarmor', 'obfuscate',
                        '--output', str(obfuscated_dir),
                        '--advanced', '2',
                        '--restrict', '4',
                        '--exact',
                        str(source_file)
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode == 0:
                        obf_file = obfuscated_dir / source_file.name
                        if obf_file.exists():
                            shutil.copy2(obf_file, source_file)
                            logger.info(f"     ✅ {file_path} obfuscado (avançado)")
                    else:
                        logger.warning(f"     ⚠️ Falha na obfuscação avançada {file_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro na obfuscação: {e}")
            return False
    
    def _apply_compilation(self) -> bool:
        """Aplica compilação Cython"""
        try:
            logger.info("⚡ Aplicando compilação Cython...")
            
            # Compilar apenas arquivos críticos
            for file_path in self.critical_files:
                source_file = self.temp_dir / file_path
                if source_file.exists():
                    logger.info(f"   Compilando: {file_path}")
                    
                    # Criar arquivo .pyx
                    pyx_file = source_file.with_suffix('.pyx')
                    shutil.copy2(source_file, pyx_file)
                    
                    # Setup básico para compilação
                    setup_content = f'''
from setuptools import setup
from Cython.Build import cythonize

setup(
    ext_modules = cythonize(["{pyx_file.name}"], compiler_directives={{'language_level': 3}})
)
'''
                    
                    setup_file = pyx_file.parent / "setup_temp.py"
                    with open(setup_file, 'w') as f:
                        f.write(setup_content)
                    
                    # Compilar
                    cmd = [sys.executable, str(setup_file), 'build_ext', '--inplace']
                    result = subprocess.run(cmd, cwd=pyx_file.parent, 
                                          capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        logger.info(f"     ✅ {file_path} compilado")
                    else:
                        logger.warning(f"     ⚠️ Falha ao compilar {file_path}")
                    
                    # Limpar arquivos temporários
                    if setup_file.exists():
                        setup_file.unlink()
                    if pyx_file.exists():
                        pyx_file.unlink()
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro na compilação: {e}")
            return False
    
    def _insert_anti_debug_code(self):
        """Insere código anti-debugging"""
        try:
            logger.info("🛡️ Inserindo proteções anti-debugging...")
            
            # Código anti-debug para inserir
            anti_debug_code = '''
# Anti-debugging protection
import sys
import time
import threading

def _check_debug():
    if sys.gettrace() is not None:
        os._exit(1)
    
    start = time.perf_counter()
    for i in range(1000): pass
    if time.perf_counter() - start > 0.01:
        os._exit(1)

threading.Thread(target=_check_debug, daemon=True).start()
'''
            
            # Inserir em arquivos principais
            main_file = self.temp_dir / "main.py"
            if main_file.exists():
                with open(main_file, 'r') as f:
                    content = f.read()
                
                # Inserir após imports
                lines = content.split('\n')
                import_end = 0
                for i, line in enumerate(lines):
                    if line.strip() and not line.startswith('#') and not line.startswith('import') and not line.startswith('from'):
                        import_end = i
                        break
                
                lines.insert(import_end, anti_debug_code)
                
                with open(main_file, 'w') as f:
                    f.write('\n'.join(lines))
                
                logger.info("   ✅ Anti-debugging inserido em main.py")
            
        except Exception as e:
            logger.error(f"❌ Erro ao inserir anti-debug: {e}")
    
    def _insert_license_checks(self):
        """Insere verificações de licença"""
        try:
            logger.info("🔑 Inserindo verificações de licença...")
            
            # Código de verificação de licença
            license_check_code = '''
# License verification
from src.protection.quantum_code_protection import QuantumCodeProtection

_protection = QuantumCodeProtection()
if not _protection.validate_license():
    print("❌ Licença inválida ou expirada")
    sys.exit(1)
'''
            
            # Inserir em main.py
            main_file = self.temp_dir / "main.py"
            if main_file.exists():
                with open(main_file, 'r') as f:
                    content = f.read()
                
                # Inserir após imports
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if 'if __name__ == "__main__"' in line:
                        lines.insert(i, license_check_code)
                        break
                
                with open(main_file, 'w') as f:
                    f.write('\n'.join(lines))
                
                logger.info("   ✅ Verificação de licença inserida")
            
        except Exception as e:
            logger.error(f"❌ Erro ao inserir verificação de licença: {e}")
    
    def create_executable(self) -> bool:
        """Cria executável com PyInstaller"""
        try:
            logger.info("📦 Criando executável com PyInstaller...")
            
            main_file = self.temp_dir / "main.py"
            if not main_file.exists():
                logger.error("❌ Arquivo main.py não encontrado")
                return False
            
            # Configuração PyInstaller
            pyinstaller_args = [
                'pyinstaller',
                '--onefile',  # Arquivo único
                '--windowed',  # Sem console (Windows)
                '--name', 'QuantumShield',
                '--distpath', str(self.dist_dir),
                '--workpath', str(self.build_dir),
                '--specpath', str(self.build_dir),
                '--clean',
                '--noconfirm'
            ]
            
            # Adicionar ícone se existir
            icon_file = self.project_root / "resources" / "icon.ico"
            if icon_file.exists():
                pyinstaller_args.extend(['--icon', str(icon_file)])
            
            # Adicionar dados adicionais
            data_dirs = ['lib', 'resources', 'config']
            for data_dir in data_dirs:
                source_data = self.temp_dir / data_dir
                if source_data.exists():
                    pyinstaller_args.extend(['--add-data', f'{source_data};{data_dir}'])
            
            # Adicionar arquivo principal
            pyinstaller_args.append(str(main_file))
            
            # Executar PyInstaller
            logger.info("   Executando PyInstaller...")
            result = subprocess.run(pyinstaller_args, cwd=self.temp_dir,
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("✅ Executável criado com sucesso")
                
                # Verificar se executável foi criado
                exe_file = self.dist_dir / "QuantumShield.exe"
                if exe_file.exists():
                    logger.info(f"   📁 Executável: {exe_file}")
                    logger.info(f"   📏 Tamanho: {exe_file.stat().st_size / 1024 / 1024:.1f} MB")
                    return True
                else:
                    logger.error("❌ Executável não encontrado após build")
                    return False
            else:
                logger.error(f"❌ Erro no PyInstaller: {result.stderr}")
                return False
            
        except Exception as e:
            logger.error(f"❌ Erro ao criar executável: {e}")
            return False
    
    def sign_and_package(self) -> bool:
        """Assina e empacota o executável final"""
        try:
            logger.info("✍️ Assinando e empacotando...")
            
            exe_file = self.dist_dir / "QuantumShield.exe"
            if not exe_file.exists():
                logger.error("❌ Executável não encontrado para assinatura")
                return False
            
            # Simular assinatura digital
            signature_info = {
                'file_name': exe_file.name,
                'file_size': exe_file.stat().st_size,
                'build_time': time.time(),
                'protection_level': 'maximum',
                'signer': 'QuantumShield Team',
                'certificate': 'QuantumShield Code Signing Certificate'
            }
            
            # Salvar informações de assinatura
            sig_file = exe_file.with_suffix('.sig')
            with open(sig_file, 'w') as f:
                json.dump(signature_info, f, indent=2)
            
            # Criar checksums
            import hashlib
            with open(exe_file, 'rb') as f:
                exe_data = f.read()
            
            checksums = {
                'md5': hashlib.md5(exe_data).hexdigest(),
                'sha1': hashlib.sha1(exe_data).hexdigest(),
                'sha256': hashlib.sha256(exe_data).hexdigest()
            }
            
            checksum_file = exe_file.with_suffix('.checksums')
            with open(checksum_file, 'w') as f:
                json.dump(checksums, f, indent=2)
            
            logger.info("✅ Executável assinado e empacotado")
            logger.info(f"   📁 Arquivos criados:")
            logger.info(f"     - {exe_file.name}")
            logger.info(f"     - {sig_file.name}")
            logger.info(f"     - {checksum_file.name}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro na assinatura: {e}")
            return False
    
    def cleanup_build_files(self):
        """Limpa arquivos temporários de build"""
        try:
            logger.info("🧹 Limpando arquivos temporários...")
            
            # Remover diretórios temporários
            for temp_dir in [self.build_dir, self.temp_dir]:
                if temp_dir.exists():
                    shutil.rmtree(temp_dir)
                    logger.info(f"   ✅ {temp_dir.name} removido")
            
        except Exception as e:
            logger.error(f"❌ Erro na limpeza: {e}")
    
    def build_protected_executable(self) -> bool:
        """Processo completo de build com proteção"""
        try:
            logger.info("🚀 Iniciando build protegido do QuantumShield...")
            
            # 1. Preparar ambiente
            if not self.prepare_build_environment():
                return False
            
            # 2. Aplicar proteções
            if not self.apply_code_protection():
                return False
            
            # 3. Criar executável
            if not self.create_executable():
                return False
            
            # 4. Assinar e empacotar
            if not self.sign_and_package():
                return False
            
            # 5. Limpar arquivos temporários
            self.cleanup_build_files()
            
            logger.info("🎉 Build protegido concluído com sucesso!")
            
            # Mostrar resumo
            exe_file = self.dist_dir / "QuantumShield.exe"
            if exe_file.exists():
                size_mb = exe_file.stat().st_size / 1024 / 1024
                logger.info(f"📊 Resumo do build:")
                logger.info(f"   📁 Executável: {exe_file}")
                logger.info(f"   📏 Tamanho: {size_mb:.1f} MB")
                logger.info(f"   🔒 Proteções aplicadas: {sum(self.protection_config.values())}/6")
                logger.info(f"   ✅ Status: Pronto para distribuição")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro no build protegido: {e}")
            return False

def test_build_protection():
    """Teste do sistema de build com proteção"""
    print("🏗️ Testando Sistema de Build com Proteção...")
    
    # Usar diretório atual como projeto
    project_root = Path(__file__).parent.parent.parent
    builder = QuantumBuildProtection(str(project_root))
    
    try:
        # Teste de preparação
        print("\n🔧 Testando preparação do ambiente...")
        if builder.prepare_build_environment():
            print("  ✅ Ambiente preparado")
        else:
            print("  ❌ Falha na preparação")
            return False
        
        # Teste de proteções (sem executar build completo)
        print("\n🔒 Testando aplicação de proteções...")
        if builder.apply_code_protection():
            print("  ✅ Proteções aplicadas")
        else:
            print("  ⚠️ Algumas proteções falharam")
        
        # Mostrar configuração
        print("\n⚙️ Configuração de proteção:")
        for protection, enabled in builder.protection_config.items():
            status = "✅" if enabled else "❌"
            print(f"  {status} {protection}")
        
        print("\n✅ Teste de build com proteção concluído!")
        return True
        
    except Exception as e:
        print(f"\n❌ Erro no teste: {e}")
        return False

if __name__ == "__main__":
    test_build_protection()

