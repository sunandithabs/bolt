from datetime import datetime

from rich.console import Console
from rich.table import Table

from detector.event_log import EventLog


def render(log: EventLog):
    console = Console()
    table = Table(title="BOLT — Attack Suite Results")

    table.add_column("Time")
    table.add_column("Attack")
    table.add_column("Version")
    table.add_column("Result")
    table.add_column("Detail")

    for e in log.events:
        style = "green" if e.result == "BLOCKED" else "bold red"
        ts = datetime.fromtimestamp(e.timestamp).strftime("%H:%M:%S")
        table.add_row(ts, e.attack_name, str(e.version), e.result, e.detail, style=style)

    console.print(table)

    summary = log.summary()
    console.print(
        f"\n{summary['blocked']}/{summary['total']} attacks blocked, "
        f"{summary['succeeded']} succeeded."
    )
