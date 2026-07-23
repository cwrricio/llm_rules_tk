#!/usr/bin/env bash
# Teste completo — Rules Farmer (configuração do artigo)
#
# Roda o pipeline completo para UM ataque com a MESMA configuração usada no artigo:
#   - 1 ataque base + 49 variantes evasivas  = 50 execuções
#   - convergência declarada após 20 detecções consecutivas
#   - até 10 tentativas de (re)geração de regra por ciclo
#
# ATENÇÃO: é uma execução LONGA e faz MUITAS chamadas ao LLM (custo de tokens
# proporcional). Use o teste mínimo (scripts/teste_minimo.sh) para uma verificação
# rápida; use este para reproduzir a escala do artigo.
#
# Requisitos: Docker + uma chave de API no .env (ver README, "Fluxo de avaliação").
# Uso:  ./scripts/teste_completo.sh
#       ./scripts/teste_completo.sh --keep
#       RF_PROVIDER=deepseek RF_MODEL=deepseek-v4-pro ./scripts/teste_completo.sh
set -euo pipefail

cd "$(dirname "$0")/.."

exec uv run --python 3.12 python pipeline_local/run_pipeline.py \
  --variant-count 49 \
  --convergence-threshold 20 \
  --max-iterations 10 \
  "$@"
