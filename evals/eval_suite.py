"""Model Armor filter evaluation suite.

Usage:
  python eval_suite.py --config moderate
  python eval_suite.py --compare strict,moderate,permissive,prompt-only
  python eval_suite.py --template demo-template-prompt --category edge
  python eval_suite.py --config strict --output json --save results.json
  python eval_suite.py --config strict --direction response
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from dotenv import find_dotenv, load_dotenv
from google.api_core import exceptions as gcp_exceptions
from google.cloud import dlp_v2 as dlp
from google.cloud import modelarmor_v1 as ma
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from eval_cases import CASES, PRESETS, ConfigPreset, EvalCase

load_dotenv(find_dotenv(usecwd=True))

console = Console()

PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "")
DEFAULT_REGION = os.environ.get("MODEL_ARMOR_REGION") or os.environ.get("GCP_REGION", "us-central1")

_ENABLED = 1
_DISABLED = 2


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class EvalResult:
    case: EvalCase
    actual: str                     # "pass" | "block" | "error"
    triggered_filters: list[str]
    elapsed_ms: int
    outcome: str                    # "TP" | "TN" | "FP" | "FN" | "ERR"
    error: Optional[str] = None


@dataclass
class EvalRun:
    config_name: str
    template_name: str
    results: list[EvalResult] = field(default_factory=list)

    @property
    def tp(self) -> int:
        return sum(1 for r in self.results if r.outcome == "TP")

    @property
    def tn(self) -> int:
        return sum(1 for r in self.results if r.outcome == "TN")

    @property
    def fp(self) -> int:
        return sum(1 for r in self.results if r.outcome == "FP")

    @property
    def fn(self) -> int:
        return sum(1 for r in self.results if r.outcome == "FN")

    @property
    def fp_on_good(self) -> int:
        return sum(1 for r in self.results if r.outcome == "FP" and r.case.category == "good")

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


# ---------------------------------------------------------------------------
# Template building
# ---------------------------------------------------------------------------

def build_template_from_preset(preset: ConfigPreset, dlp_template_name: Optional[str]) -> ma.Template:
    confidence_map = {
        "LOW_AND_ABOVE": ma.DetectionConfidenceLevel.LOW_AND_ABOVE,
        "MEDIUM_AND_ABOVE": ma.DetectionConfidenceLevel.MEDIUM_AND_ABOVE,
        "HIGH": ma.DetectionConfidenceLevel.HIGH,
    }

    rai_filters = [
        ma.RaiFilterSettings.RaiFilter(
            filter_type=ma.RaiFilterType[name],
            confidence_level=confidence_map[conf],
        )
        for name, conf in preset.rai_filters
    ]

    if dlp_template_name and preset.sdp_info_types:
        sdp_settings = ma.SdpFilterSettings(
            advanced_config=ma.SdpAdvancedConfig(inspect_template=dlp_template_name)
        )
    else:
        sdp_settings = ma.SdpFilterSettings()

    return ma.Template(
        filter_config=ma.FilterConfig(
            pi_and_jailbreak_filter_settings=ma.PiAndJailbreakFilterSettings(
                filter_enforcement=_ENABLED if preset.pi_enabled else _DISABLED,
                confidence_level=confidence_map[preset.pi_confidence],
            ),
            malicious_uri_filter_settings=ma.MaliciousUriFilterSettings(
                filter_enforcement=_ENABLED if preset.uri_enabled else _DISABLED,
            ),
            rai_settings=ma.RaiFilterSettings(rai_filters=rai_filters),
            sdp_settings=sdp_settings,
        )
    )


def ensure_dlp_template(preset: ConfigPreset, project_id: str, region: str) -> Optional[str]:
    """Create a DLP inspect template for the preset's info types. Returns name or None."""
    if not preset.sdp_info_types:
        return None

    dlp_client = dlp.DlpServiceClient()
    parent = f"projects/{project_id}/locations/{region}"
    template_id = f"eval-dlp-{preset.name}"
    template_name = f"{parent}/inspectTemplates/{template_id}"

    try:
        dlp_client.create_inspect_template(
            request=dlp.CreateInspectTemplateRequest(
                parent=parent,
                inspect_template=dlp.InspectTemplate(
                    display_name=f"Model Armor Eval DLP — {preset.name}",
                    inspect_config=dlp.InspectConfig(
                        info_types=[dlp.InfoType(name=t) for t in preset.sdp_info_types],
                        min_likelihood=dlp.Likelihood.POSSIBLE,
                    ),
                ),
                template_id=template_id,
            )
        )
    except gcp_exceptions.AlreadyExists:
        pass
    except Exception as e:
        console.print(f"[yellow]Warning: could not create DLP template for {preset.name}: {e}[/yellow]")
        return None

    return template_name


def ensure_temp_template(
    preset: ConfigPreset,
    client: ma.ModelArmorClient,
    project_id: str,
    region: str,
) -> str:
    """Create (or recreate) a temporary eval template. Returns full resource name."""
    parent = f"projects/{project_id}/locations/{region}"
    template_id = f"eval-temp-{preset.name}"
    template_name = f"{parent}/templates/{template_id}"

    dlp_template_name = ensure_dlp_template(preset, project_id, region)

    try:
        client.delete_template(request=ma.DeleteTemplateRequest(name=template_name))
    except gcp_exceptions.NotFound:
        pass

    template = build_template_from_preset(preset, dlp_template_name)
    client.create_template(
        request=ma.CreateTemplateRequest(
            parent=parent,
            template_id=template_id,
            template=template,
        )
    )
    return template_name


def cleanup_temp_template(template_name: str, client: ma.ModelArmorClient) -> None:
    try:
        client.delete_template(request=ma.DeleteTemplateRequest(name=template_name))
    except Exception as e:
        console.print(f"[yellow]Warning: cleanup failed for {template_name}: {e}[/yellow]")


# ---------------------------------------------------------------------------
# Result extraction
# ---------------------------------------------------------------------------

def extract_result(sanitization_result) -> tuple[str, list[str]]:
    """Returns (actual: 'pass'|'block', triggered_filters: list[str])."""
    matched = sanitization_result.filter_match_state == ma.FilterMatchState.MATCH_FOUND
    actual = "block" if matched else "pass"
    triggered: list[str] = []

    for key, fr in sanitization_result.filter_results.items():
        if key == "pi_and_jailbreak":
            if fr.pi_and_jailbreak_filter_result.match_state == ma.FilterMatchState.MATCH_FOUND:
                triggered.append("pi_and_jailbreak")
        elif key == "rai":
            if fr.rai_filter_result.match_state == ma.FilterMatchState.MATCH_FOUND:
                triggered.append("rai")
        elif key == "sdp":
            ir = fr.sdp_filter_result.inspect_result
            if ir and ir.match_state == ma.FilterMatchState.MATCH_FOUND:
                triggered.append("sdp")
        elif key == "malicious_uris":
            if fr.malicious_uri_filter_result.match_state == ma.FilterMatchState.MATCH_FOUND:
                triggered.append("malicious_uri")

    return actual, triggered


def classify_outcome(expected: str, actual: str) -> str:
    if expected == "block" and actual == "block":
        return "TP"
    if expected == "pass" and actual == "pass":
        return "TN"
    if expected == "block" and actual == "pass":
        return "FN"
    return "FP"


# ---------------------------------------------------------------------------
# Main eval loop
# ---------------------------------------------------------------------------

def _call_api(
    case: EvalCase,
    template_name: str,
    client: ma.ModelArmorClient,
):
    """Call the appropriate Model Armor API for the case direction."""
    if case.direction == "prompt":
        return client.sanitize_user_prompt(
            request=ma.SanitizeUserPromptRequest(
                name=template_name,
                user_prompt_data=ma.DataItem(text=case.prompt),
            )
        ).sanitization_result
    else:
        return client.sanitize_model_response(
            request=ma.SanitizeModelResponseRequest(
                name=template_name,
                model_response_data=ma.DataItem(text=case.prompt),
            )
        ).sanitization_result


def run_eval(
    template_name: str,
    config_name: str,
    cases: list[EvalCase],
    client: ma.ModelArmorClient,
    delay: float = 0.5,
) -> EvalRun:
    run = EvalRun(config_name=config_name, template_name=template_name)

    with console.status(f"Running [cyan]{len(cases)}[/cyan] cases against [bold]{config_name}[/bold]...") as status:
        for i, case in enumerate(cases, 1):
            status.update(f"[{i}/{len(cases)}] {case.id} — {case.name}")
            start = time.time()

            try:
                sanitization_result = _call_api(case, template_name, client)
                elapsed_ms = round((time.time() - start) * 1000)
                actual, triggered = extract_result(sanitization_result)
                outcome = classify_outcome(case.expected, actual)
                run.results.append(EvalResult(
                    case=case, actual=actual, triggered_filters=triggered,
                    elapsed_ms=elapsed_ms, outcome=outcome,
                ))

            except gcp_exceptions.ResourceExhausted:
                # Exponential backoff: 2s, 4s, 8s
                last_exc = None
                for wait in (2, 4, 8):
                    time.sleep(wait)
                    try:
                        sanitization_result = _call_api(case, template_name, client)
                        elapsed_ms = round((time.time() - start) * 1000)
                        actual, triggered = extract_result(sanitization_result)
                        outcome = classify_outcome(case.expected, actual)
                        run.results.append(EvalResult(
                            case=case, actual=actual, triggered_filters=triggered,
                            elapsed_ms=elapsed_ms, outcome=outcome,
                        ))
                        last_exc = None
                        break
                    except gcp_exceptions.ResourceExhausted as e:
                        last_exc = e
                if last_exc is not None:
                    elapsed_ms = round((time.time() - start) * 1000)
                    run.results.append(EvalResult(
                        case=case, actual="error", triggered_filters=[],
                        elapsed_ms=elapsed_ms, outcome="ERR", error=str(last_exc),
                    ))

            except Exception as e:
                elapsed_ms = round((time.time() - start) * 1000)
                run.results.append(EvalResult(
                    case=case, actual="error", triggered_filters=[],
                    elapsed_ms=elapsed_ms, outcome="ERR", error=str(e),
                ))

            if i < len(cases):
                time.sleep(delay)

    return run


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------

_OUTCOME_STYLE = {
    "TP": "[green]✓ TP[/green]",
    "TN": "[green]✓ TN[/green]",
    "FP": "[bold red]✗ FP[/bold red]",
    "FN": "[bold red]✗ FN[/bold red]",
    "ERR": "[yellow]⚠ ERR[/yellow]",
}

_CAT_STYLE = {
    "good": "[green]good[/green]",
    "bad": "[red]bad[/red]",
    "edge": "[yellow]edge[/yellow]",
}


def render_run_table(run: EvalRun) -> None:
    table = Table(
        title=f"Eval Results — {run.config_name}",
        box=box.ROUNDED,
        show_lines=False,
        highlight=True,
    )
    table.add_column("ID", style="dim", width=6)
    table.add_column("Name", min_width=30)
    table.add_column("Cat", width=5)
    table.add_column("Dir", width=5)
    table.add_column("Exp", width=6)
    table.add_column("Got", width=6)
    table.add_column("Result", width=8)
    table.add_column("Triggered filters", min_width=20)
    table.add_column("ms", width=6, justify="right")

    for r in run.results:
        triggered_str = ", ".join(r.triggered_filters) if r.triggered_filters else ""
        name_str = f"[bold red]{r.case.name}[/bold red]" if r.outcome in ("FP", "FN") else r.case.name

        table.add_row(
            r.case.id,
            name_str,
            _CAT_STYLE.get(r.case.category, r.case.category),
            r.case.direction[:4],
            r.case.expected,
            r.actual,
            _OUTCOME_STYLE.get(r.outcome, r.outcome),
            triggered_str,
            str(r.elapsed_ms),
        )

    console.print(table)
    _render_summary(run)


def _render_summary(run: EvalRun) -> None:
    fps = [r for r in run.results if r.outcome == "FP"]
    fns = [r for r in run.results if r.outcome == "FN"]
    errs = [r for r in run.results if r.outcome == "ERR"]
    fp_color = "bold red" if run.fp_on_good > 0 else "green"

    lines = [
        f"Config: [cyan]{run.config_name}[/cyan]   "
        f"Template: [dim]{run.template_name}[/dim]   Cases: {len(run.results)}",
        f"TP: [green]{run.tp}[/green]   TN: [green]{run.tn}[/green]   "
        f"FP: [bold red]{run.fp}[/bold red]   FN: [bold red]{run.fn}[/bold red]",
        f"Precision: {run.precision:.3f}   Recall: {run.recall:.3f}   F1: {run.f1:.3f}",
        f"FP on GOOD cases: [{fp_color}]{run.fp_on_good}[/{fp_color}]   "
        f"← most important for enterprise",
        "",
    ]

    if fps:
        lines.append("False Positives (wrongly blocked):")
        for r in fps:
            lines.append(f"  {r.case.id}  {r.case.name}  [triggered: {', '.join(r.triggered_filters)}]")
    else:
        lines.append("[green]False Positives: (none)[/green]")

    if fns:
        lines.append("False Negatives (missed blocks):")
        for r in fns:
            lines.append(f"  {r.case.id}  {r.case.name}  [expected: {r.case.expected_filter}]")
    else:
        lines.append("[green]False Negatives: (none)[/green]")

    if errs:
        lines.append(f"[yellow]Errors: {len(errs)} case(s) failed with API errors[/yellow]")
        for r in errs:
            lines.append(f"  {r.case.id}  {r.error}")

    console.print(Panel("\n".join(lines), title="Summary", border_style="blue"))


def render_compare_table(runs: list[EvalRun]) -> None:
    table = Table(title="Config Comparison", box=box.ROUNDED)
    table.add_column("Config", min_width=14)
    table.add_column("TP", justify="right", width=4)
    table.add_column("TN", justify="right", width=4)
    table.add_column("FP", justify="right", width=4)
    table.add_column("FN", justify="right", width=4)
    table.add_column("Precision", justify="right", width=10)
    table.add_column("Recall", justify="right", width=8)
    table.add_column("F1", justify="right", width=7)
    table.add_column("FP on Good", justify="right", width=11)

    for run in runs:
        fp_good_str = (
            f"[bold red]{run.fp_on_good}[/bold red]"
            if run.fp_on_good > 0
            else f"[green]{run.fp_on_good}[/green]"
        )
        table.add_row(
            f"[cyan]{run.config_name}[/cyan]",
            f"[green]{run.tp}[/green]",
            f"[green]{run.tn}[/green]",
            f"[bold red]{run.fp}[/bold red]" if run.fp else f"[green]{run.fp}[/green]",
            f"[bold red]{run.fn}[/bold red]" if run.fn else f"[green]{run.fn}[/green]",
            f"{run.precision:.3f}",
            f"{run.recall:.3f}",
            f"{run.f1:.3f}",
            fp_good_str,
        )

    console.print(table)

    # Recommendation
    no_fp_runs = [r for r in runs if r.fp_on_good == 0]
    if no_fp_runs:
        best = max(no_fp_runs, key=lambda r: r.f1)
        console.print(Panel(
            f"→ Recommendation: [bold cyan]{best.config_name}[/bold cyan] — "
            f"highest F1 ({best.f1:.3f}) with zero false positives on legitimate content.",
            border_style="green",
        ))
    else:
        best = min(runs, key=lambda r: (r.fp_on_good, -r.f1))
        console.print(Panel(
            f"→ Recommendation: [bold cyan]{best.config_name}[/bold cyan] — "
            f"fewest FPs on good cases ({best.fp_on_good}), F1: {best.f1:.3f}.\n"
            f"[yellow]Note: all configs produced false positives on legitimate content. "
            f"Consider further tuning.[/yellow]",
            border_style="yellow",
        ))


def to_json(runs: list[EvalRun]) -> dict:
    return {
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "runs": [
            {
                "config": run.config_name,
                "template": run.template_name,
                "summary": {
                    "tp": run.tp, "tn": run.tn, "fp": run.fp, "fn": run.fn,
                    "fp_on_good": run.fp_on_good,
                    "precision": round(run.precision, 4),
                    "recall": round(run.recall, 4),
                    "f1": round(run.f1, 4),
                },
                "results": [
                    {
                        "id": r.case.id,
                        "name": r.case.name,
                        "category": r.case.category,
                        "direction": r.case.direction,
                        "expected": r.case.expected,
                        "actual": r.actual,
                        "outcome": r.outcome,
                        "triggered_filters": r.triggered_filters,
                        "elapsed_ms": r.elapsed_ms,
                        **({"error": r.error} if r.error else {}),
                    }
                    for r in run.results
                ],
            }
            for run in runs
        ],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="eval_suite.py",
        description="Model Armor filter evaluation suite.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python eval_suite.py --config moderate\n"
            "  python eval_suite.py --compare strict,moderate,permissive,prompt-only\n"
            "  python eval_suite.py --template demo-template-prompt --category edge\n"
            "  python eval_suite.py --config strict --direction response\n"
            "  python eval_suite.py --compare strict,moderate --save results.json\n"
        ),
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--template", metavar="TEMPLATE_ID",
        help="Use an existing deployed template ID (e.g. demo-template-prompt).",
    )
    source.add_argument(
        "--config", metavar="CONFIG_NAME",
        choices=list(PRESETS.keys()),
        help=f"Named preset — creates a temp template. Choices: {', '.join(PRESETS.keys())}.",
    )
    source.add_argument(
        "--compare", metavar="CONFIG1,CONFIG2,...",
        help="Comma-separated preset names to run and compare side by side.",
    )

    parser.add_argument(
        "--region", default=None,
        help="Model Armor region (default: GCP_REGION from .env).",
    )
    parser.add_argument(
        "--category", action="append", choices=["good", "bad", "edge"],
        help="Filter by category (repeatable). Default: all.",
    )
    parser.add_argument(
        "--direction", choices=["prompt", "response"],
        help="Filter by direction. Default: both.",
    )
    parser.add_argument(
        "--output", choices=["table", "json"], default="table",
        help="Output format (default: table).",
    )
    parser.add_argument(
        "--save", metavar="FILE",
        help="Save JSON results to this file.",
    )
    parser.add_argument(
        "--delay", type=float, default=0.5,
        help="Seconds to wait between API calls (default: 0.5).",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not PROJECT_ID:
        console.print("[red]Error: GCP_PROJECT_ID not set. Copy .env.example to .env and fill it in.[/red]")
        sys.exit(1)

    region = args.region or DEFAULT_REGION
    api_endpoint = f"modelarmor.{region}.rep.googleapis.com"
    parent = f"projects/{PROJECT_ID}/locations/{region}"
    client = ma.ModelArmorClient(client_options={"api_endpoint": api_endpoint})

    # Apply case filters
    cases = list(CASES)
    if args.category:
        cases = [c for c in cases if c.category in args.category]
    if args.direction:
        cases = [c for c in cases if c.direction == args.direction]

    if not cases:
        console.print("[yellow]No cases match the specified filters.[/yellow]")
        sys.exit(0)

    console.print(
        f"\n[bold]Model Armor Eval Suite[/bold] — "
        f"{len(cases)} cases | region: [cyan]{region}[/cyan]\n"
    )

    runs: list[EvalRun] = []

    if args.compare:
        config_names = [n.strip() for n in args.compare.split(",")]
        unknown = [n for n in config_names if n not in PRESETS]
        if unknown:
            console.print(f"[red]Unknown config(s): {', '.join(unknown)}. "
                          f"Available: {', '.join(PRESETS.keys())}[/red]")
            sys.exit(1)

        for name in config_names:
            preset = PRESETS[name]
            console.print(f"[bold]Creating template:[/bold] [cyan]{name}[/cyan] — {preset.description}")
            template_name = ensure_temp_template(preset, client, PROJECT_ID, region)
            try:
                run = run_eval(template_name, name, cases, client, args.delay)
                runs.append(run)
            finally:
                cleanup_temp_template(template_name, client)

        if args.output == "table":
            for run in runs:
                render_run_table(run)
                console.print()
            render_compare_table(runs)

    elif args.config:
        preset = PRESETS[args.config]
        console.print(f"[bold]Creating template:[/bold] [cyan]{args.config}[/cyan] — {preset.description}")
        template_name = ensure_temp_template(preset, client, PROJECT_ID, region)
        try:
            run = run_eval(template_name, args.config, cases, client, args.delay)
            runs.append(run)
        finally:
            cleanup_temp_template(template_name, client)

        if args.output == "table":
            render_run_table(run)

    else:  # --template
        template_name = f"{parent}/templates/{args.template}"
        console.print(f"[bold]Using existing template:[/bold] [cyan]{template_name}[/cyan]")
        run = run_eval(template_name, args.template, cases, client, args.delay)
        runs.append(run)

        if args.output == "table":
            render_run_table(run)

    # JSON output
    result_dict = to_json(runs)
    if args.save:
        with open(args.save, "w") as f:
            json.dump(result_dict, f, indent=2)
        console.print(f"\n[green]Results saved to {args.save}[/green]")
    if args.output == "json":
        print(json.dumps(result_dict, indent=2))


if __name__ == "__main__":
    main()
