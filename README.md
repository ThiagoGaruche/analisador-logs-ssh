# Analisador de Logs SSH

Script em Python que analisa o arquivo auth.log de servidores Linux e identifica:

- Tentativas de login falhas
- IPs com muitas falhas (possível força bruta)
- Usuários mais visados
- Falhas em horário suspeito (00h às 05h)
- Logins bem-sucedidos após várias falhas (alerta crítico)

## Como usar

python analisador.py exemplos/auth_exemplo.log
python analisador.py exemplos/auth_exemplo.log -o relatorio.txt

Requer apenas Python 3, sem bibliotecas externas.

## Aviso

Os logs de exemplo são fictícios. Use esta ferramenta apenas em logs de sistemas seus ou autorizados.
