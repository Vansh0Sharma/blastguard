"""Hosted-workflow assertions only; never execute submitted Bash or print its data."""

import json
import os
from pathlib import Path
import stat


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def main():
    outputs = json.loads(os.environ["CHECK_OUTPUTS"])
    require(isinstance(outputs, dict), "Outputs were not an object")
    require(
        set(outputs) <= {"decision", "exit-code", "report-path"},
        "Unexpected action output field",
    )
    require(outputs.get("decision") == os.environ["EXPECT_DECISION"], "Wrong decision")
    require(outputs.get("exit-code") == os.environ["EXPECT_CODE"], "Wrong exit-code")
    require(os.environ["CHECK_OUTCOME"] == os.environ["EXPECT_OUTCOME"], "Wrong step outcome")

    workspace = Path("e2e-workspace")
    require(workspace.is_dir(), "Test workspace is missing")
    require(not Path("blastguard-should-not-exist").exists(), "Input executed in checkout")
    require(
        not (workspace / "blastguard-should-not-exist").exists(),
        "Input executed in analysis directory",
    )
    report = os.environ["EXPECT_REPORT"]
    files = {str(path.relative_to(workspace)) for path in workspace.rglob("*") if path.is_file()}
    require(files == ({report} if report else set()), "Unexpected workspace file mutation")
    require(
        outputs.get("report-path", "") == (f"e2e-workspace/{report}" if report else ""),
        "Wrong report-path output",
    )
    if report:
        path = workspace / report
        require(not path.is_symlink(), "Report is a symlink")
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, "Report is not owner-only")
        raw = path.read_text(encoding="utf-8")
        synthetic_secret = "-".join(["synthetic", "ci-value", "123456"])
        require(synthetic_secret not in raw, "Secret fixture leaked into report")
        require(synthetic_secret not in json.dumps(outputs), "Secret fixture leaked into outputs")
        value = json.loads(raw)
        require(value.get("schema_version") == "1.0", "Wrong report schema")
        require(value.get("decision") == os.environ["EXPECT_DECISION"], "Wrong report decision")
        require("[REDACTED" in value.get("command", ""), "Report command was not redacted")
    print("Hosted action assertions passed: decision, exit-code, outcome, no execution, report boundary")


if __name__ == "__main__":
    main()
