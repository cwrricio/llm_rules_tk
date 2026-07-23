# Thin Snort 3 image for the self-contained pipeline.
#
# Reuses the upstream Snort 3 build (ciscotalos/snort3) and only:
#   1. exposes the snort binary on PATH as `snort` (the production
#      SnortRuleValidator calls `docker exec <container> snort ...`);
#   2. sets a long-running entrypoint so the container stays alive for
#      `docker exec` (rule validation and pcap replay) without needing a live
#      capture interface — no NET_RAW/NET_ADMIN capabilities required.
FROM ciscotalos/snort3:latest
USER root
RUN ln -sf /home/snorty/snort3/bin/snort /usr/local/bin/snort
ENTRYPOINT ["sleep"]
CMD ["infinity"]
