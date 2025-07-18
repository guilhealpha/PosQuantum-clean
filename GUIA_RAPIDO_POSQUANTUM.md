# GUIA RÁPIDO DO POSQUANTUM

## INSTALAÇÃO

1. **Baixe o executável:**
   - Acesse: https://github.com/guilhealpha/PosQuantum-clean/releases/tag/v3.0
   - Baixe o arquivo `PosQuantum-Windows.exe`

2. **Execute o programa:**
   - Clique duas vezes no arquivo baixado
   - Se aparecer um aviso de segurança, clique em "Mais informações" e depois em "Executar assim mesmo"

## INTERFACE PRINCIPAL

A interface do PosQuantum é organizada em 16 abas, cada uma com funcionalidades específicas:

![Interface Principal](https://github.com/guilhealpha/PosQuantum-clean/raw/master/assets/interface_principal.png)

## GUIA RÁPIDO POR MÓDULO

### 1. CRIPTOGRAFIA PÓS-QUÂNTICA

- **Gerar chaves ML-KEM:**
  - Selecione o nível de segurança (512, 768, 1024)
  - Clique em "Gerar Par de Chaves"
  - Salve as chaves pública e privada

- **Encapsular chave:**
  - Carregue a chave pública do destinatário
  - Clique em "Encapsular"
  - Salve o texto cifrado e a chave compartilhada

- **Decapsular chave:**
  - Carregue sua chave privada
  - Carregue o texto cifrado
  - Clique em "Decapsular"
  - A chave compartilhada será exibida

### 2. VPN PÓS-QUÂNTICA

- **Conectar à VPN:**
  - Selecione um servidor da lista
  - Escolha o nível de segurança
  - Clique em "Conectar"

- **Configurar Split Tunneling:**
  - Vá para a aba "Configurações"
  - Selecione os aplicativos que devem usar a VPN
  - Clique em "Salvar"

### 3. BLOCKCHAIN PÓS-QUÂNTICO

- **Visualizar blockchain:**
  - A aba mostra os blocos mais recentes
  - Clique em um bloco para ver detalhes

- **Criar transação:**
  - Clique em "Nova Transação"
  - Preencha os detalhes
  - Assine com sua chave privada
  - Clique em "Enviar"

### 4-16. OUTROS MÓDULOS

Cada módulo possui uma interface intuitiva com botões e campos específicos para suas funcionalidades. Explore cada aba para descobrir todas as possibilidades do PosQuantum.

## ATALHOS DE TECLADO

- **Ctrl+N:** Nova chave
- **Ctrl+S:** Salvar
- **Ctrl+O:** Abrir arquivo
- **Ctrl+E:** Encriptar
- **Ctrl+D:** Decriptar
- **F1:** Ajuda

## SOLUÇÃO DE PROBLEMAS COMUNS

- **Programa não inicia:**
  - Verifique se você tem permissões de administrador
  - Instale o Visual C++ Redistributable mais recente

- **Erro de conexão VPN:**
  - Verifique sua conexão com a internet
  - Tente outro servidor
  - Desative temporariamente o firewall

- **Erro de criptografia:**
  - Verifique se as chaves estão corretas
  - Tente um nível de segurança diferente

## SUPORTE

Para suporte adicional:
- **GitHub:** https://github.com/guilhealpha/PosQuantum-clean/issues
- **Documentação completa:** Consulte os arquivos incluídos na pasta `docs`

