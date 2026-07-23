# xrce-dds-udp-dos attack image (self-contained pipeline).
#
# Pure standard-library Python — no pip install, no network at build time, so
# `rebuild_attack_image` (called by the Attack Agent after each source mutation)
# is fast and works offline.
FROM python:3.12-slim
WORKDIR /app
COPY attack_udp_dos.py /app/attack_udp_dos.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
