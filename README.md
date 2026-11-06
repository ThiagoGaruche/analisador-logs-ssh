# 🛡️ SSH Log Analyzer

Um script em Python para automação de análise de arquivos de log de autenticação SSH (`auth.log`). O projeto identifica padrões de tentativas incorretas de login, lista os alvos e endereços IP mais frequentes e sinaliza possíveis ataques de força bruta, emitindo alertas críticos caso um IP atacante tenha obtido acesso ao sistema.

---

## 🚀 Funcionalidades

- **Contagem Total de Falhas:** Mapeia a quantidade global de senhas incorretas.
- **Top 5 IPs Atacantes:** Exibe os endereços IP com maior número de falhas.
- **Top 5 Usuários Visados:** Identifica os nomes de usuário mais visados (ex: `root`, `admin`).
- **Detecção de Força Bruta:** Filtra IPs que ultrapassam o limite configurável de falhas (padrão: 5).
- **Alerta de Invasão/Comprometimento:** Identifica se um IP com histórico de falhas conseguiu realizar login com sucesso posteriormente.
- **Análise Temporal:** Soma as tentativas ocorridas no horário da madrugada (00h às 05h).
- **Exportação:** Opção para salvar o relatório em arquivo `.txt`.

---

## 📋 Pré-requisitos

- **Python 3.x** instalado.
- Nenhuma biblioteca de terceiros é necessária (utiliza apenas os módulos nativos `re`, `argparse` e `collections`).

---

## 💻 Como Usar

### 1. Clonar o Repositório
```bash
git clone [https://github.com/SEU_USUARIO/NOME_DO_REPOSITORIO.git](https://github.com/SEU_USUARIO/NOME_DO_REPOSITORIO.git)
cd NOME_DO_REPOSITORIO
