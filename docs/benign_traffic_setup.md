# Configuração de Servidores para Tráfego Benigno

O módulo `benign_traffic.py` gera tráfego legítimo de três protocolos para testar a taxa de
falsos positivos das regras Snort geradas. Este documento lista quais servidores precisam estar
rodando em **Entity 2 (192.168.137.1)** para cada protocolo.

---

## Servidores Necessários em Entity 2

### 1. XRCE-DDS Agent (porta 8888)

**Status:** Já em execução (serviço padrão do testbed).

O Agent microXRCE-DDS já está rodando como parte da infraestrutura do experimento.
O script de tráfego benigno XRCE (`benign_traffic.py`, protocolo `"xrce"`) envia pings
legítimos para este Agent.

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
from rules_farmer.ssh import SSHClient

# Construir via app_factory ou injetar manualmente
runner = BenignTrafficRunner(
    ssh_client=attacker_ssh,  # SSH para Entity 3
    target_ip="192.168.137.1",
)

# Rodar tráfego benigno XRCE por 30s (Agent já está rodando)
result = runner.run(protocol="xrce", duration_seconds=30)
print(result.stdout)

# MQTT (mosquitto deve estar rodando)
result = runner.run(protocol="mqtt", duration_seconds=30)

# HTTP (nginx deve estar rodando)
result = runner.run(protocol="http", duration_seconds=30, target_port=80)
```

---

## Procedimento de Validação de Falsos Positivos

1. Deploy da regra Snort a ser testada (via `IDSRuleInjector.inject()`)
2. Limpar o alert log (`IDSMonitor.clear_alert_log()`)
3. Executar tráfego benigno por 60 segundos (`BenignTrafficRunner.run(...)`)
4. Verificar se a regra disparou (`IDSMonitor.check_fired(sid)`)
5. Se `fired=True`: a regra tem FALSO POSITIVO — não é válida para deploy em produção
6. Se `fired=False`: a regra passa na validação de benigno

Este procedimento deve ser incorporado como fase obrigatória no orquestrador após a convergência
de cada experimento.

---

## Resumo de Servidores

| Protocolo | Porta | Serviço | Status no Testbed | Ação Necessária |
|-----------|-------|---------|-------------------|-----------------|
| XRCE-DDS  | 8888  | microXRCE-DDS Agent | ✅ Já rodando | Nenhuma |
| MQTT      | 1883  | Eclipse Mosquitto   | ❓ Verificar    | `apt install mosquitto` se não instalado |
| HTTP      | 80    | nginx               | ❓ Verificar    | `apt install nginx` se não instalado |
