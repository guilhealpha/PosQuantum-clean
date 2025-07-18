# PERGUNTAS FREQUENTES (FAQ) - POSQUANTUM

## PERGUNTAS GERAIS

### O que é o PosQuantum?
O PosQuantum é um software completo de segurança que oferece proteção contra ameaças quânticas e clássicas. Ele inclui 16 módulos principais com mais de 70 funcionalidades, abrangendo desde criptografia pós-quântica até blockchain, VPN, armazenamento distribuído e muito mais.

### O que é criptografia pós-quântica?
A criptografia pós-quântica refere-se a algoritmos criptográficos que são resistentes a ataques de computadores quânticos. Os computadores quânticos, quando totalmente desenvolvidos, poderão quebrar muitos dos algoritmos criptográficos atualmente em uso, como RSA e ECC. Os algoritmos pós-quânticos, como ML-KEM, ML-DSA e SPHINCS+, são projetados para resistir a esses ataques.

### O PosQuantum é seguro?
Sim, o PosQuantum implementa os algoritmos pós-quânticos aprovados pelo NIST (ML-KEM, ML-DSA, SPHINCS+) e segue as melhores práticas de segurança. O software foi projetado para atender aos requisitos de certificações como FIPS 140-3, Common Criteria EAL4, ISO 27001 e SOC 2 Type II.

### Quais são os requisitos de sistema?
- **Sistema Operacional:** Windows 10/11 (64 bits)
- **Processador:** Intel Core i5 ou equivalente
- **Memória RAM:** 8GB ou superior
- **Espaço em Disco:** 100MB para instalação
- **Conexão Internet:** Recomendada para algumas funcionalidades

## INSTALAÇÃO E USO

### Como instalo o PosQuantum?
O PosQuantum é distribuído como um executável portátil que não requer instalação. Basta baixar o arquivo `PosQuantum-Windows.exe` e executá-lo.

### Preciso de permissões de administrador para executar o PosQuantum?
Para algumas funcionalidades, como a VPN pós-quântica, são necessárias permissões de administrador. Recomendamos executar o programa como administrador para garantir o acesso completo a todas as funcionalidades.

### O PosQuantum funciona em outros sistemas operacionais além do Windows?
Atualmente, o executável pré-compilado está disponível apenas para Windows. Versões para Linux e macOS estão em desenvolvimento e serão disponibilizadas em breve.

### Como atualizo o PosQuantum para a versão mais recente?
Basta baixar a versão mais recente do executável e substituir a versão anterior. Suas configurações e chaves serão preservadas.

## FUNCIONALIDADES

### Quais algoritmos pós-quânticos o PosQuantum suporta?
O PosQuantum suporta os algoritmos aprovados pelo NIST:
- ML-KEM (FIPS 203) para encapsulamento de chaves
- ML-DSA (FIPS 204) para assinatura digital
- SPHINCS+ (FIPS 205) para assinatura baseada em hash
- Além disso, implementa um sistema híbrido de curva elíptica com proteção pós-quântica

### Como funciona a VPN pós-quântica?
A VPN pós-quântica do PosQuantum utiliza o protocolo proprietário QuantumShield, que combina criptografia pós-quântica com protocolos tradicionais para garantir a segurança das comunicações. Ela inclui recursos como Kill Switch, Split Tunneling e seleção automática de servidores.

### O que é o blockchain pós-quântico?
O blockchain pós-quântico é uma implementação de ledger distribuído que utiliza algoritmos pós-quânticos para assinatura e verificação de transações, garantindo que a blockchain permaneça segura mesmo contra ataques de computadores quânticos.

### Como funciona o sistema de identidade?
O sistema de identidade do PosQuantum permite a criação, emissão, verificação e revogação de credenciais digitais com proteção pós-quântica. Ele utiliza ML-DSA para assinatura digital e inclui autenticação multifator para maior segurança.

## SEGURANÇA E PRIVACIDADE

### O PosQuantum coleta dados dos usuários?
Não, o PosQuantum não coleta dados dos usuários. Todas as operações são realizadas localmente no seu computador, e nenhuma informação é enviada para servidores externos, exceto quando explicitamente solicitado pelo usuário (como no caso da VPN ou blockchain).

### Como o PosQuantum protege minhas chaves privadas?
As chaves privadas são armazenadas localmente e protegidas por criptografia AES-256. Além disso, o módulo HSM Virtual fornece um ambiente seguro para operações criptográficas, isolando o material sensível do resto do sistema.

### O PosQuantum é resistente a ataques de side-channel?
Sim, o PosQuantum implementa várias medidas para mitigar ataques de side-channel, como execução em tempo constante, proteção contra análise de consumo de energia e proteção contra ataques de cache.

### Como posso verificar se o executável do PosQuantum é autêntico?
O executável é assinado digitalmente e inclui um hash SHA-256 que pode ser verificado para garantir sua autenticidade. Você pode verificar a assinatura e o hash na página de releases do GitHub.

## SUPORTE E DESENVOLVIMENTO

### Como reporto um bug ou solicito uma nova funcionalidade?
Você pode reportar bugs e solicitar novas funcionalidades através do sistema de issues do GitHub: https://github.com/guilhealpha/PosQuantum-clean/issues

### O PosQuantum é de código aberto?
Sim, o PosQuantum é um projeto de código aberto. O código-fonte está disponível no GitHub e pode ser auditado, modificado e distribuído de acordo com os termos da licença.

### Como posso contribuir para o desenvolvimento do PosQuantum?
Você pode contribuir de várias formas:
- Reportando bugs e sugerindo melhorias
- Enviando pull requests com correções e novas funcionalidades
- Ajudando na documentação e tradução
- Testando o software e fornecendo feedback

### Onde posso encontrar mais documentação sobre o PosQuantum?
A documentação completa está disponível na pasta `docs` do repositório GitHub e inclui manuais de usuário, guias de desenvolvimento, especificações técnicas e exemplos de uso.

