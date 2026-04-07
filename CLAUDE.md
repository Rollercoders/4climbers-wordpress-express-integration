# Claude Code - Istruzioni di progetto

## Git workflow

- **Non committare mai direttamente su `develop` o `main`.**
- Ogni feature/fix va su un branch dedicato (`feature/...`, `fix/...`).
- Creare il branch **prima** di qualsiasi commit.
- Aprire sempre una PR verso `develop`.

## CI/CD

- Il push su `develop` triggera una build e un deploy automatico.
- I commit con messaggio che inizia con `chore:` non triggerano il deploy.
