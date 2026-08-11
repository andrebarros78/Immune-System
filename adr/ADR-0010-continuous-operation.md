# ADR-0010 — Operação contínua soberana

## Estado
Aceito para a Fase 10.

## Contexto
As Fases 1–9 provaram contratos, execução isolada, cognição sem autoridade, observabilidade, diagnóstico/correção, experiência operacional, aprendizagem controlada e cenários ponta a ponta. Faltava manter essas capacidades vivas após reinício, falha parcial e atualização.

## Decisão

1. `ContinuousSupervisor` é o coordenador contínuo e **não** recebe autoridade de execução de host.
2. No boot ele chama a retomada durável existente e recupera leases expirados; não cria uma segunda fila.
3. Auto-health é persistido como evidência e heartbeat. Falha de probe degrada o runtime, mas não derruba o Core.
4. `HeartbeatWatchdog` é somente leitura. Heartbeat vencido vira `STALE`; reinício de processo pertence ao gerenciador de serviço do SO.
5. Instância única usa lock local com recuperação de lock comprovadamente obsoleto.
6. Backups SQLite são consistentes, SHA-256 verificados e passam por `integrity_check`; restore drill usa destino isolado.
7. Retenção de backup é limitada e nunca apaga os backups mais recentes abaixo do piso configurado.
8. Atualizações são locais e staged. O bundle possui manifesto completo de SHA-256 e symlinks são rejeitados.
9. Antes da ativação existe backup verificado do estado. O ponteiro da release muda atomicamente.
10. Health gate falho restaura o ponteiro anterior e remove a release rejeitada.
11. Versões avançam monotonicamente; downgrade exige um rollback explícito para release previamente verificada.
12. O runtime possui entrypoint independente de IA. A indisponibilidade de Provider não impede Supervisor, backup ou Watchdog.
13. Autostart é portátil: systemd e Windows Boot Task reiniciam o processo sem conceder bypass de privilégio.
14. `MISSION_PROVEN` da Fase 10, se emitido, possui escopo explícito de **implementação do repositório e operação controlada em CI**. Não afirma tempo físico indefinido de 24x7 em um host ainda não instalado.

## Consequências
A instalação em um host específico passa a ser um escopo de implantação, não uma lacuna arquitetural do módulo. Qualquer implantação deve preservar os mesmos gates de identidade, política, checkpoint, backup e evidência.
