# TShark local

```bash
./setup_tools.sh
```

Cria `tools/tshark/bin/tshark` apontando pro binário do sistema (Wireshark não copia bem entre máquinas).

O FastAPI usa esse path em `find_tool("tshark")`.
