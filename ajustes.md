1. O "Catalogo" de ataques funciona assim:

unipampa@unipampa:~/ataques/attackers-claude/xrce-dds-discovery-poison$ ls attack_discovery_poison.c Dockerfile install.sh compile.sh entrypoint.sh README.md unipampa@unipampa:~/ataques/attackers-claude/xrce-dds-discovery-poison$ cd .. unipampa@unipampa:~/ataques/attackers-claude$ cd xrce-dds- xrce-dds-discovery-poison/ xrce-dds-session-hijack/ xrce-dds-entity-flood/ xrce-dds-time-desync/ xrce-dds-fragment-abuse/ xrce-dds-udp-dos/ xrce-dds-malformed-inject/ unipampa@unipampa:~/ataques/attackers-claude$ cd xrce-dds-fragment-abuse/ unipampa@unipampa:~/ataques/attackers-claude/xrce-dds-fragment-abuse$ ls attack_fragment_abuse.c Dockerfile install.sh compile.sh entrypoint.sh README.md unipampa@unipampa:~/ataques/attackers-claude/xrce-dds-fragment-abuse$ cd .. unipampa@unipampa:~/ataques/attackers-claude$ cd mqtt- mqtt-bruteforce/ mqtt-publisher-flood/ mqtt-lwt-abuse/ mqtt-qos-amplification/ unipampa@unipampa:~/ataques/attackers-claude$ cd mqtt-publisher-flood/ unipampa@unipampa:~/ataques/attackers-claude/mqtt-publisher-flood$ ls Dockerfile entrypoint.sh README.md unipampa@unipampa:~/ataques/attackers-claude/mqtt-publisher-flood$


2. Preciso que ajuste o sistema de forma que ele consiga (vendo estrutura_ids e estrutura_attacks) criar regras, adicionar regras, testar, criar uma pasta temporaria - Rodar entrypoints, rodar os ataques, ver qual ataque o usuario quer et etc

3. Não deve ter um "catalogo" dentro desse codigo.

4. Preciso também que organize bem um readme
    4.1 Instalar depencias, iniciar uv, rodar o sistema 
    4.2 O sistema deve esperar um retorno textual do prompt do usuario no terminal