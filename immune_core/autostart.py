from __future__ import annotations

import html
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


class AutostartError(RuntimeError):
    pass


@dataclass(frozen=True)
class AutostartPlan:
    name: str
    command: tuple[str, ...]
    working_directory: str
    restart_seconds: int = 5

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.command:
            raise AutostartError("service name and command are required")
        if self.restart_seconds < 1 or self.restart_seconds > 300:
            raise AutostartError("restart_seconds outside 1..300")
        if any("\x00" in part for part in self.command):
            raise AutostartError("invalid service command")

    def systemd_unit(self) -> str:
        command = " ".join(shlex.quote(part) for part in self.command)
        cwd = shlex.quote(str(Path(self.working_directory)))
        return (
            "[Unit]\n"
            "Description=Sistema Imunologico Continuous Runtime\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            f"WorkingDirectory={cwd}\n"
            f"ExecStart={command}\n"
            "Restart=always\n"
            f"RestartSec={self.restart_seconds}\n"
            "NoNewPrivileges=true\n"
            "PrivateTmp=true\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )

    def windows_task_xml(self) -> str:
        exe = html.escape(self.command[0], quote=True)
        args = html.escape(" ".join(self.command[1:]), quote=True)
        cwd = html.escape(str(Path(self.working_directory)), quote=True)
        return f"""<?xml version=\"1.0\" encoding=\"UTF-16\"?>
<Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RestartOnFailure><Interval>PT{self.restart_seconds}S</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context=\"Author\">
    <Exec><Command>{exe}</Command><Arguments>{args}</Arguments><WorkingDirectory>{cwd}</WorkingDirectory></Exec>
  </Actions>
</Task>
"""


def build_runtime_plan(python_executable: str, repository_root: str | Path, extra_args: Sequence[str] = ()) -> AutostartPlan:
    root = Path(repository_root).resolve()
    script = root / "scripts" / "immune_runtime.py"
    command = (str(Path(python_executable).resolve()), str(script), *tuple(str(x) for x in extra_args))
    return AutostartPlan("immune-system", command, str(root))
