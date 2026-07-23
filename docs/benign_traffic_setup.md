# Configuração de Servidores para Tráfego Benigno

O módulo `benign_traffic.py` gera tráfego legítimo de três protocolos para testar a taxa de
falsos positivos das regras Snort geradas. Este documento lista quais servidores precisam estar
rodando em **Entity 2 (192.168.137.1)** para cada protocolo.

Cada protocolo é exercido por **vários perfis legítimos** (operação, tamanho de payload e
cadência de cliente diferentes), não um único padrão fixo. A regra precisa ficar **silenciosa em
TODOS os perfis** para passar na checagem: o alert log acumula entre perfis, então uma única
verificação após a execução reprova a regra se qualquer perfil disparar. "Passar no benigno"
deixa de significar "não disparou em 1 amostra" e passa a significar "ficou silenciosa contra um
espectro de tráfego legítimo".

---

## Servidores Necessários em Entity 2

### 1. XRCE-DDS Agent (porta 8888)

**Status:** Já em execução (serviço padrão do testbed).

O Agent microXRCE-DDS já está rodando como parte da infraestrutura do experimento.
O tráfego benigno XRCE (`benign_traffic.py`, protocolo `"xrce"`) exercita três perfis
legítimos para este Agent: **ping** (keepalive), **register** (registro de participante,
payload maior) e **heartbeat** — cada um com cadência de cliente distinta.

**Verificar:**
```bash
# No Entity 2
ss -ulnp | grep 8888
# ou
docker ps | grep xrce
```

---

### 2. Broker MQTT (porta 1883)

**Status:** Pode NÃO estar instalado — precisa verificar.

O tráfego benigno MQTT (protocolo `"mqtt"`) exercita três perfis: **publish** (QoS 0),
**subscribe** e **pingreq** (keepalive). Todos são operações padrão que o Mosquitto atende
nativamente — nenhuma configuração extra além da abaixo é necessária.

Instalar e iniciar o **Eclipse Mosquitto**:

```bash
# No Entity 2 (Ubuntu/Debian)
sudo apt-get install -y mosquitto mosquitto-clients

# Configuração mínima (sem autenticação para o testbed)
cat > /etc/mosquitto/conf.d/testbed.conf << 'EOF'
listener 1883
allow_anonymous true
EOF

sudo systemctl enable mosquitto
sudo systemctl start mosquitto

# Verificar
ss -tlnp | grep 1883
```

**Teste rápido (do Entity 3):**
```bash
mosquitto_pub -h 192.168.137.1 -t test/benign -m "hello"
```

---

### 3. Servidor HTTP (porta 80)

**Status:** Provavelmente NÃO instalado — precisa verificar.

O tráfego benigno HTTP (protocolo `"http"`) exercita três perfis: **GET**, **HEAD** e
**POST** (corpo de formulário pequeno) sobre os paths `/`, `/index.html`, `/health` e
`/status`. A configuração `return 200` abaixo responde a todos os métodos, então HEAD e POST
funcionam sem ajustes adicionais.

Instalar o **nginx** com configuração mínima:

```bash
# No Entity 2
sudo apt-get install -y nginx

# Configuração mínima com endpoint /health
cat > /etc/nginx/sites-available/testbed << 'EOF'
server {
    listen 80;
    server_name _;

    location / {
        return 200 "OK\n";
        add_header Content-Type text/plain;
    }

    location /health {
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }

    location /status {
        return 200 "running\n";
        add_header Content-Type text/plain;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/testbed /etc/nginx/sites-enabled/testbed
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl enable nginx && sudo systemctl start nginx

# Verificar
curl http://192.168.137.1/health
```

---

## Como Usar o Módulo de Tráfego Benigno

```python
from rules_farmer.benign_traffic import BenignTrafficRunner

# Construir via app_factory ou injetar manualmente
runner = BenignTrafficRunner(ssh_client=attacker_ssh)  # SSH para Entity 3

# O IP de destino (Entity 2) e a duração são argumentos de run().
# A duração TOTAL é dividida entre os perfis do protocolo (ver seções acima).

# Rodar tráfego benigno XRCE por 30s (Agent já está rodando)
result = runner.run(protocol="xrce", target_ip="192.168.137.1", duration_seconds=30)
print(result.stdout)  # stdout de cada perfil vem prefixado por [nome_do_perfil]

# MQTT (mosquitto deve estar rodando)
result = runner.run(protocol="mqtt", target_ip="192.168.137.1", duration_seconds=30)

# HTTP (nginx deve estar rodando)
result = runner.run(protocol="http", target_ip="192.168.137.1", duration_seconds=30, target_port=80)
```

---

## Procedimento de Validação de Falsos Positivos

1. Deploy da regra Snort a ser testada (via `IDSRuleInjector.inject()`)
2. Limpar o alert log (`IDSMonitor.clear_alert_log()`)
3. Executar o tráfego benigno (`BenignTrafficRunner.run(...)`) — todos os perfis do protocolo
4. Verificar se a regra disparou em qualquer perfil (`IDSMonitor.check_fired(sid)`)
5. Se `fired=True`: a regra tem FALSO POSITIVO — não é válida para deploy em produção
6. Se `fired=False`: a regra passa na validação de benigno

No pipeline, isso é a tool `run_benign_traffic(protocol, sid)`, chamada obrigatoriamente entre
`deploy_rule` e `trigger_attacker`. A obrigatoriedade é **estrutural, não só de prompt**:
`run_benign_traffic` registra o veredito no `RunContext` e `trigger_attacker` **recusa** qualquer
SID que não passou pela checagem (retorna `{"error": "benign_check_required"}` sem executar o
ataque). Um falso positivo ou erro do runner revoga a validação do SID.

---

## Resumo de Servidores

| Protocolo | Porta | Serviço | Status no Testbed | Ação Necessária |
|-----------|-------|---------|-------------------|-----------------|
| XRCE-DDS  | 8888  | microXRCE-DDS Agent | ✅ Já rodando | Nenhuma |
| MQTT      | 1883  | Eclipse Mosquitto   | ❓ Verificar    | `apt install mosquitto` se não instalado |
| HTTP      | 80    | nginx               | ❓ Verificar    | `apt install nginx` se não instalado |
