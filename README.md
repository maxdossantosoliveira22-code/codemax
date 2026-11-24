# Codermax — IP Video Gateway

Converte os streams **UDP (multicast/unicast) do modulador/encoder** em links
**HLS (.m3u8)**, **MPEG-TS (.ts)** e listas **M3U** para uso externo, com painel web.

- Porta própria (**30024/TCP**) — convive com o Flussonic sem conflito
- Captura **passiva** dos UDP (AF_PACKET): não ocupa nenhuma porta UDP
- Scanner automático de streams na placa de rede local (identifica nome, codec, MPTS)
- Mosaico ao vivo, gráficos de bitrate, erros de continuidade (CC), CPU/RAM
- Conexões ativas (derrubar cliente), limite de espectadores, backup/restauração

## Instalação (terminal SSH, 1 linha)

```bash
curl -fsSL https://raw.githubusercontent.com/maxdossantosoliveira22-code/codemax/main/instalar-codermax.sh | sudo bash -s -- --usuario SEU_USUARIO --senha SUA_SENHA
```

Painel: `http://IP_DO_SERVIDOR:30024`

Outras opções:

```bash
# outra porta
curl -fsSL https://raw.githubusercontent.com/maxdossantosoliveira22-code/codemax/main/instalar-codermax.sh | sudo bash -s -- --porta 30025

# desinstalar (mantém os canais em /opt/codermax/data)
curl -fsSL https://raw.githubusercontent.com/maxdossantosoliveira22-code/codemax/main/instalar-codermax.sh | sudo bash -s -- --desinstalar
```

Comandos úteis: `systemctl status codermax`, `journalctl -u codermax -f`

## Desenvolvimento

`codermax.py` (backend, só biblioteca padrão do Python + ffmpeg) e `web/` (interface).
`bash build.sh` gera o `instalar-codermax.sh` com tudo embutido.
