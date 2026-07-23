#!/usr/bin/env bash
# Teste mínimo — Rules Farmer (Salão de Ferramentas SBSeg)
#
# Roda o pipeline completo de ponta a ponta para UM ataque, com poucas variações:
# 1 ataque base + 1 variante evasiva (execução rápida, ~poucos minutos). Serve para o
# avaliador verificar e AUDITAR visualmente todas as etapas da ferramenta.
#
# Requisitos: Docker + uma chave de API no .env (ver README, "Fluxo de avaliação").
# Uso:  ./scripts/teste_minimo.sh                 (provedor/modelo do .env / config)
#       ./scripts/teste_minimo.sh --keep          (mantém o Snort de pé ao final)
#       RF_PROVIDER=openai RF_MODEL=gpt-4o ./scripts/teste_minimo.sh
set -euo pipefail

# Roda a partir da raiz do repositório, independentemente de onde o script foi chamado.
cd "$(dirname "$0")/.."

exec uv run --python 3.12 python pipeline_local/run_pipeline.py \
  --variant-count 1 \
  --convergence-threshold 1 \
  "$@"
