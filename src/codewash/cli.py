"""CLI definition for codewash using Typer."""

from __future__ import annotations

import json
import sys
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich import print as rprint

from codewash import __version__
from codewash.config import load_config, write_default_config
from codewash.detector import detect_file
from codewash.models import Category
from codewash.replacer import MAPPING_FILENAME, anonymize, restore as do_restore
from codewash.scanner import scan

app = typer.Typer(
    name="codewash",
    help="Anonymize code repositories for safe AI processing.",
    add_completion=True,
    pretty_exceptions_enable=False,
)

console = Console()
err_console = Console(stderr=True)

# Category → colour mapping for display
_CATEGORY_COLOURS: dict[Category, str] = {
    Category.IP_ADDRESS: "yellow",
    Category.DOMAIN: "cyan",
    Category.REGISTRY_URL: "magenta",
    Category.EMAIL: "blue",
    Category.API_KEY: "red",
    Category.PASSWORD: "red bold",
    Category.PRIVATE_KEY: "red bold",
    Category.AWS_RESOURCE: "orange3",
    Category.INTERNAL_HOSTNAME: "green",
    Category.GIT_REMOTE: "bright_cyan",
    Category.CUSTOM: "white",
}


class OutputFormat(str, Enum):
    text = "text"
    json = "json"


# ---------------------------------------------------------------------------
# Version callback
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"codewash {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    pass


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


@app.command()
def scan(
    directory: Path = typer.Argument(..., help="Directory to scan.", exists=True, file_okay=False),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed findings per file."),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to .codewash.yaml"),
    fmt: OutputFormat = typer.Option(OutputFormat.text, "--format", "-f", help="Output format."),
) -> None:
    """Scan a directory and show what would be anonymized (dry-run)."""
    cfg = load_config(config_file, source_dir=directory)
    files = scan_module(directory, cfg)

    if fmt == OutputFormat.text:
        console.rule("[bold blue]codewash scan[/bold blue]")
        console.print(f"Scanning: [bold]{directory}[/bold]")
        console.print()

    all_findings: list[dict] = []
    total_findings = 0

    for path in files:
        findings = detect_file(path, config=cfg)
        if not findings:
            continue

        rel = path.relative_to(directory).as_posix()
        total_findings += len(findings)

        if fmt == OutputFormat.json:
            for f in findings:
                all_findings.append(
                    {
                        "file": rel,
                        "line": f.line,
                        "column": f.column,
                        "category": f.category.value,
                        "value": f.replace_value,
                    }
                )
        else:
            if verbose or True:  # always show per-file details
                console.print(f"  [bold]▸ {rel}[/bold]")
                for f in findings:
                    colour = _CATEGORY_COLOURS.get(f.category, "white")
                    label = f.category.label.ljust(8)
                    console.print(
                        f"    [yellow]⚠[/yellow] [[{colour}]{label}[/{colour}]]"
                        f"  L{f.line}:  [dim]{f.replace_value[:80]}[/dim]"
                    )
                console.print()

    if fmt == OutputFormat.json:
        result = {
            "directory": str(directory),
            "files_scanned": len(files),
            "total_findings": total_findings,
            "findings": all_findings,
        }
        typer.echo(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        console.rule()
        console.print(f"  Files scanned:  [bold]{len(files)}[/bold]")
        console.print(f"  Findings:       [bold]{total_findings}[/bold]")
        console.print()
        if total_findings > 0:
            console.print("Run [bold cyan]codewash anon <DIR>[/bold cyan] to create an anonymized copy.")

    # Exit code 2 when findings exist
    if total_findings > 0:
        raise typer.Exit(code=2)


# ---------------------------------------------------------------------------
# anon command
# ---------------------------------------------------------------------------


@app.command()
def anon(
    source: Path = typer.Argument(..., help="Source directory.", exists=True, file_okay=False),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory."),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to .codewash.yaml"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing output directory."),
) -> None:
    """Anonymize a directory and create a sanitized copy."""
    cfg = load_config(config_file, source_dir=source)

    out_dir = output or source.parent / (source.name + "_anon")

    if out_dir.exists() and not force:
        overwrite = typer.confirm(
            f"Output directory '{out_dir}' already exists. Overwrite?", default=False
        )
        if not overwrite:
            console.print("[yellow]Aborted.[/yellow]")
            raise typer.Exit(code=0)
        import shutil
        shutil.rmtree(out_dir)

    console.rule("[bold blue]codewash anon[/bold blue]")
    console.print(f"Source:  [bold]{source}[/bold]")
    console.print(f"Output:  [bold]{out_dir}[/bold]")

    from codewash.scanner import walk_all as _walk_all

    scanned_files = scan_module(source, cfg)
    all_files = _walk_all(source, cfg)
    scanned_set = set(scanned_files)

    console.print(f"Rules:   [bold]{_count_rules(cfg)} patterns loaded[/bold]")
    console.print()

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Processing...", total=len(all_files))

        from codewash.detector import detect_file as _detect
        from codewash.replacer import Replacer
        import shutil as _shutil

        replacer = Replacer()
        from codewash.models import Stats
        stats = Stats(files_scanned=len(all_files))

        # First pass: detect findings in scanned files only
        file_findings: dict[Path, list] = {}
        for f in scanned_files:
            findings = _detect(f, config=cfg)
            file_findings[f] = findings
            for finding in findings:
                replacer.get_or_create(finding.replace_value, finding.category)
                stats.increment(finding.category)
                rel = f.relative_to(source).as_posix()
                replacer.record_file(finding.replace_value, rel)

        # Second pass: copy all files; apply replacements only to scanned files
        out_dir.mkdir(parents=True, exist_ok=True)
        for f in all_files:
            rel = f.relative_to(source)
            dest = out_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)

            if f not in scanned_set:
                _shutil.copy2(f, dest)
            else:
                findings = file_findings[f]
                if not findings:
                    _shutil.copy2(f, dest)
                else:
                    try:
                        content = f.read_text(encoding="utf-8", errors="replace")
                        new_content, n = replacer.apply_to_text(content, findings)
                        dest.write_text(new_content, encoding="utf-8")
                        if new_content != content:
                            stats.files_modified += 1
                            stats.replacements_made += n
                    except OSError:
                        _shutil.copy2(f, dest)
            progress.advance(task)

        map_path = replacer.save_mapping(out_dir)

    console.rule()
    console.print("[bold green]Done[/bold green]")
    console.print(f"  Files processed: [bold]{stats.files_scanned}[/bold]")
    console.print(f"  Files modified:  [bold]{stats.files_modified}[/bold]")
    console.print(f"  Replacements:    [bold]{stats.replacements_made}[/bold]")
    console.print(f"  Mapping saved:   [bold]{map_path}[/bold]")


# ---------------------------------------------------------------------------
# restore command
# ---------------------------------------------------------------------------


@app.command()
def restore(
    anon_dir: Path = typer.Argument(..., help="Anonymized directory to restore.", exists=True, file_okay=False),
    map_file: Optional[Path] = typer.Option(None, "--map", "-m", help="Path to mapping file."),
) -> None:
    """Restore original values in an anonymized directory."""
    map_path = map_file or (anon_dir / MAPPING_FILENAME)

    if not map_path.exists():
        err_console.print(f"[red]Error:[/red] Mapping file not found: {map_path}")
        raise typer.Exit(code=1)

    console.rule("[bold blue]codewash restore[/bold blue]")
    console.print(f"Directory: [bold]{anon_dir}[/bold]")
    console.print(f"Mapping:   [bold]{map_path}[/bold]")
    console.print()

    stats = do_restore(anon_dir, map_path)

    console.rule()
    console.print("[bold green]Done[/bold green]")
    console.print(f"  Files restored: [bold]{stats.files_modified}[/bold]")


# ---------------------------------------------------------------------------
# init command
# ---------------------------------------------------------------------------


@app.command()
def init(
    directory: Path = typer.Argument(
        ".", help="Directory to write .codewash.yaml into."
    ),
) -> None:
    """Create an annotated .codewash.yaml in the current directory."""
    target = Path(directory) / ".codewash.yaml"

    if target.exists():
        err_console.print(
            f"[yellow]Warning:[/yellow] {target} already exists. Aborting to avoid overwrite."
        )
        raise typer.Exit(code=1)

    write_default_config(target)
    console.print(f"[green]✓[/green] Created [bold]{target}[/bold]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def scan_module(directory: Path, cfg) -> list[Path]:
    """Thin wrapper around scanner.scan with a friendly import alias."""
    from codewash.scanner import scan as _scan
    files = _scan(directory, cfg)
    if not files:
        console.print("[dim]No relevant files found.[/dim]")
    else:
        console.print(f"Found [bold]{len(files)}[/bold] relevant files")
        console.print()
    return files


def _count_rules(cfg) -> int:
    """Count total active patterns."""
    from codewash.patterns import BUILTIN_PATTERNS
    return len(BUILTIN_PATTERNS) + len(cfg.additional_patterns)
