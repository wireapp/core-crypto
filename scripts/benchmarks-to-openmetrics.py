#!/usr/bin/env python3
"""Convert JMH and tinybench benchmark results into Prometheus OpenMetrics 1.0 text.

Usage:
    scripts/benchmarks-to-openmetrics.py -f {jmh,tinybench} [RESULTS ...]
        [--extra-labels NAME=VALUE ...] [-o OUTPUT]

RESULTS may be a JSON file holding an array of benchmark results, or a
directory of such files (merged, read in sorted filename order). It defaults to
the output location of the harness given by --format:

    crypto-ffi/bindings/jvm/build/reports/jmh/results.json   (--format jmh)
    crypto-ffi/bindings/js/benches_result                    (--format tinybench)

One invocation handles one harness; results whose shape does not match
--format are an error rather than something to guess at. When OUTPUT is
omitted the exposition is written to stdout, so it can be piped straight into a
file or a Pushgateway. Note that two expositions cannot simply be concatenated
(each is terminated by `# EOF` and may not repeat a family's metadata), so push
each harness as its own job.

Both harnesses map onto one schema, all gauges:

    benchmark_score                    the primary metric
    benchmark_score_error              absolute uncertainty of the score
    benchmark_score_percentile         score distribution, keyed by `quantile`
    benchmark_score_median_deviation   median absolute deviation (tinybench)
    benchmark_samples                  number of measurements collected

`--extra-labels` adds a label to every sample in the exposition, and may be
repeated (`--extra-labels target=jvm --extra-labels os=linux`). Use it to
separate runs of the same benchmark that this script cannot tell apart on its
own -- the platform a binding was benchmarked on, a CI run id, a git ref.

Every sample carries the same identity labels: `harness` ("jmh"/"tinybench"),
`benchmark`, `mode` (thrpt, avgt, ...), `unit` (the score unit, e.g. "ops/s")
and one label per benchmark parameter (cipherSuite, userCount, ...). Two extra
labels appear only where they mean something: `quantile` (0.0 .. 1.0) on the
percentile family, and `confidence` on the error family, because the harnesses
disagree on the interval they report -- see SCORE_ERROR_HELP below. A family
with nothing to report is omitted rather than filled with NaN, which is why
tinybench emits no percentiles beyond the median and JMH emits no median
deviation.

The harnesses differ in one more way worth spelling out: JMH reports either
throughput or latency depending on the benchmark's mode, while tinybench
reports both at once. So a tinybench task becomes two series that differ only
in `mode`/`unit` -- `mode="thrpt"` in ops/s and `mode="avgt"` in ns/op --
which is exactly how JMH would model the same pair of measurements.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Iterable, NamedTuple

SCORE = "benchmark_score"
SCORE_ERROR = "benchmark_score_error"
SCORE_PERCENTILE = "benchmark_score_percentile"
SCORE_MEDIAN_DEVIATION = "benchmark_score_median_deviation"
SAMPLES = "benchmark_samples"

SCORE_ERROR_HELP = (
    "Absolute margin of error of the score, in the score unit. The confidence "
    "label gives the interval: JMH reports a 99.9% mean error, tinybench a 95% "
    "relative margin of error, so the two are not directly comparable."
)

# JMH's scoreError is the half-width of a 99.9% confidence interval; tinybench
# derives its rme from Benchmark.js' 95% t-table.
JMH_CONFIDENCE = "0.999"
TINYBENCH_CONFIDENCE = "0.95"

# tinybench measures in milliseconds; toCustomBenchmarkEntries() reports
# latency in nanoseconds, which is JMH's `ns/op` under another name.
TINYBENCH_LATENCY_UNIT = "ns/op"

# Keys of the `Label: value ± error` lines that toCustomBenchmarkEntries()
# packs into a result's `extra` field.
EXTRA_AVERAGE_LATENCY = "Average Latency (ns)"
EXTRA_MEDIAN_LATENCY = "Median Latency (ns)"
EXTRA_MEDIAN_THROUGHPUT = "Median Throughput (ops/s)"
EXTRA_SAMPLES = "Samples"

MEDIAN_QUANTILE = "0.5"

# Labels this script derives from the results; --extra-labels may not set them,
# because overriding one would misdescribe the sample it is attached to.
RESERVED_LABELS = frozenset(
    {"harness", "benchmark", "mode", "unit", "quantile", "confidence"}
)
LABEL_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")

NAN = float("nan")

# A leading decimal number, optionally in exponent notation.
NUMBER = re.compile(r"[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")


class Measurement(NamedTuple):
    """A value plus its uncertainty, both in the value's own unit."""

    value: float
    error: float


MISSING = Measurement(NAN, NAN)


class Series(NamedTuple):
    """One benchmark measurement under one mode, ready to emit."""

    labels: dict[str, str]
    confidence: str
    score: Measurement
    # quantile label value -> score at that quantile.
    percentiles: dict[str, float]
    median_deviation: float
    samples: float


def escape_label_value(value: str) -> str:
    """Escape a label value per the OpenMetrics text format."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def format_labels(labels: dict[str, str]) -> str:
    """Render a label set as `{k="v",...}`, sorted for stable output."""
    if not labels:
        return ""
    inner = ",".join(
        f'{key}="{escape_label_value(str(value))}"'
        for key, value in sorted(labels.items())
    )
    return "{" + inner + "}"


def format_value(value: float) -> str:
    """Render a float the way OpenMetrics expects (finite -> decimal)."""
    if value != value:  # NaN
        return "NaN"
    if value == float("inf"):
        return "+Inf"
    if value == float("-inf"):
        return "-Inf"
    return repr(float(value))


def sample(name: str, labels: dict[str, str], value: float) -> str:
    return f"{name}{format_labels(labels)} {format_value(value)}"


def to_float(value: Any) -> float:
    """Coerce a JSON scalar to a float, mapping anything else to NaN.

    Both harnesses can put "NaN" in as a JSON *string* -- JMH for a scoreError
    with a single measurement, tinybench wherever a table cell was empty.
    """
    if isinstance(value, bool) or value is None:
        return NAN
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return NAN


def quantile_label(percentile: str) -> str:
    """Turn a JMH percentile key ("99.99") into a quantile label ("0.9999").

    Decimal keeps the result exact, avoiding the float noise a plain `/ 100`
    would introduce.
    """
    try:
        return str((Decimal(percentile) / Decimal(100)).normalize())
    except InvalidOperation:
        return percentile


def parse_number(text: Any) -> float:
    """Read the leading number out of `text`, or NaN if there isn't one."""
    if isinstance(text, str):
        match = NUMBER.match(text.strip())
        return float(match.group()) if match else NAN
    return to_float(text)


def parse_measurement(text: Any) -> Measurement:
    """Parse a `12390123 ± 0.83%` / `12400000 ± 200000` / `81` reading.

    A percentage error is relative to the value, so it gets scaled into the
    value's unit; that keeps benchmark_score_error in the score unit for every
    harness.
    """
    if not isinstance(text, str):
        return Measurement(to_float(text), NAN)

    raw_value, _, raw_error = text.partition("±")
    value = parse_number(raw_value)
    error = parse_number(raw_error) if raw_error.strip() else NAN
    if "%" in raw_error:
        error = abs(value) * error / 100
    return Measurement(value, error)


def parse_extra(extra: Any) -> dict[str, Measurement]:
    """Parse tinybench's newline-separated `Label: value ± error` block."""
    readings: dict[str, Measurement] = {}
    if not isinstance(extra, str):
        return readings
    for line in extra.splitlines():
        label, separator, reading = line.partition(":")
        if separator:
            readings[label.strip()] = parse_measurement(reading)
    return readings


def parse_name_labels(name: str) -> dict[str, str]:
    """Split a tinybench result name into `benchmark` plus parameter labels.

    Names look like `Add a User - cipherSuite=Mls128... userCount=1`: the task
    name after the separator is the parameter set the benchmark ran with, which
    is where JMH would have a `params` object. Anything in there that isn't a
    `key=value` pair is kept verbatim under a `task` label rather than silently
    dropped.
    """
    benchmark, separator, task = name.partition(" - ")
    labels: dict[str, str] = {}
    leftovers: list[str] = []

    for token in task.split() if separator else []:
        key, is_pair, value = token.partition("=")
        if is_pair and key:
            labels[key] = value
        else:
            leftovers.append(token)

    if leftovers:
        labels["task"] = " ".join(leftovers)

    labels["benchmark"] = benchmark if separator else name
    return labels


def identity(labels: dict[str, str], harness: str, mode: str, unit: str) -> dict[str, str]:
    """Complete a parameter label set with the labels this script controls.

    Applied last, so a benchmark parameter named `mode` or `harness` cannot
    shadow the identity of the series it belongs to.
    """
    return {**labels, "harness": harness, "mode": mode, "unit": unit}


def jmh_sample_count(entry: dict[str, Any], primary: dict[str, Any]) -> float:
    """Best available measurement count for a JMH result.

    Sampling modes report `sampleCount` directly; for the others the number of
    raw per-iteration scores is the closest equivalent, and forks x iterations
    is the fallback when raw data was not retained.
    """
    count = primary.get("sampleCount")
    if count is not None:
        return to_float(count)

    raw_data = primary.get("rawData")
    if isinstance(raw_data, list):
        return float(
            sum(len(fork) for fork in raw_data if isinstance(fork, (list, tuple)))
        )

    forks = to_float(entry.get("forks"))
    iterations = to_float(entry.get("measurementIterations"))
    return forks * iterations


def read_jmh(entry: dict[str, Any]) -> list[Series]:
    primary = entry.get("primaryMetric") or {}
    labels = identity(
        {str(key): str(value) for key, value in (entry.get("params") or {}).items()}
        | {"benchmark": str(entry.get("benchmark", ""))},
        harness="jmh",
        mode=str(entry.get("mode", "")),
        unit=str(primary.get("scoreUnit", "")),
    )
    percentiles = primary.get("scorePercentiles") or {}

    return [
        Series(
            labels=labels,
            confidence=JMH_CONFIDENCE,
            score=Measurement(
                to_float(primary.get("score")), to_float(primary.get("scoreError"))
            ),
            # Sort numerically so 90.0 precedes 99.99 rather than
            # lexicographically.
            percentiles={
                quantile_label(pct): to_float(percentiles[pct])
                for pct in sorted(percentiles, key=parse_number)
            },
            median_deviation=NAN,
            samples=jmh_sample_count(entry, primary),
        )
    ]


def read_tinybench(entry: dict[str, Any]) -> list[Series]:
    name_labels = parse_name_labels(str(entry.get("name", "")))
    extra = parse_extra(entry.get("extra"))
    range_ = entry.get("range")

    # `value` is the mean throughput and `range` its margin of error, as a
    # percentage of the value.
    throughput = parse_measurement(
        f"{entry.get('value')} ± {range_}" if range_ else entry.get("value")
    )
    median_throughput = extra.get(EXTRA_MEDIAN_THROUGHPUT, MISSING)
    latency = extra.get(EXTRA_AVERAGE_LATENCY, MISSING)
    median_latency = extra.get(EXTRA_MEDIAN_LATENCY, MISSING)
    # One sample set backs both series, so both report the same count.
    samples = extra.get(EXTRA_SAMPLES, MISSING).value

    def series(mode: str, unit: str, mean: Measurement, median: Measurement) -> Series:
        return Series(
            labels=identity(name_labels, harness="tinybench", mode=mode, unit=unit),
            confidence=TINYBENCH_CONFIDENCE,
            score=mean,
            percentiles=(
                {MEDIAN_QUANTILE: median.value} if median.value == median.value else {}
            ),
            median_deviation=median.error,
            samples=samples,
        )

    return [
        series("thrpt", str(entry.get("unit", "")), throughput, median_throughput),
        series("avgt", TINYBENCH_LATENCY_UNIT, latency, median_latency),
    ]


class Harness(NamedTuple):
    """Everything that differs between the two supported result formats."""

    name: str
    default_input: Path
    read: Callable[[dict[str, Any]], list[Series]]
    # Keys a result of this format must have, used to reject a mismatched
    # --format with an actionable message instead of a pile of NaNs.
    required_keys: tuple[str, ...]


HARNESSES = {
    harness.name: harness
    for harness in (
        Harness(
            name="jmh",
            default_input=Path("crypto-ffi/bindings/jvm/build/reports/jmh/results.json"),
            read=read_jmh,
            required_keys=("benchmark", "primaryMetric"),
        ),
        Harness(
            name="tinybench",
            default_input=Path("crypto-ffi/bindings/js/benches_result"),
            read=read_tinybench,
            required_keys=("name", "value"),
        ),
    )
}


def read_entry(entry: Any, harness: Harness, source: Path) -> list[Series]:
    """Check a single result against the requested format, then convert it."""
    if not isinstance(entry, dict):
        raise ValueError(f"expected an array of objects in {source}")

    missing = [key for key in harness.required_keys if key not in entry]
    if missing:
        others = ", ".join(name for name in HARNESSES if name != harness.name)
        raise ValueError(
            f"{source} does not look like {harness.name} output: a result is "
            f"missing {', '.join(repr(key) for key in missing)}. "
            f"Try --format {others}."
        )
    return harness.read(entry)


def read_series(paths: Iterable[Path], harness: Harness) -> list[Series]:
    """Load every result from the given files and/or directories of files."""
    series: list[Series] = []
    for path in paths:
        files = sorted(path.glob("*.json")) if path.is_dir() else [path]
        for file in files:
            results = json.loads(file.read_text())
            if not isinstance(results, list):
                raise ValueError(f"expected a top-level array in {file}")
            for entry in results:
                series.extend(read_entry(entry, harness, file))
    return series


def parse_extra_labels(pairs: Iterable[str]) -> dict[str, str]:
    """Parse repeated `NAME=VALUE` arguments into a label set."""
    labels: dict[str, str] = {}
    for pair in pairs:
        name, separator, value = pair.partition("=")
        name = name.strip()
        if not separator:
            raise ValueError(f"--extra-labels expects NAME=VALUE, got {pair!r}")
        if not LABEL_NAME.fullmatch(name):
            raise ValueError(
                f"{name!r} is not a valid label name: expected letters, digits "
                "and underscores, not starting with a digit"
            )
        if name.startswith("__"):
            raise ValueError(f"{name!r} is reserved: label names may not start with __")
        if name in RESERVED_LABELS:
            raise ValueError(
                f"{name!r} is set from the benchmark results; pick another name"
            )
        if name in labels:
            raise ValueError(f"--extra-labels sets {name!r} more than once")
        if "=" in value:
            # Catches `--extra-labels target=jvm,os=linux`, which would
            # otherwise silently become one label with a comma in its value.
            raise ValueError(
                f"the value of {name!r} contains '='; pass --extra-labels once "
                "per label"
            )
        labels[name] = value
    return labels


def apply_extra_labels(series: list[Series], extra: dict[str, str]) -> list[Series]:
    """Add the extra labels to every series, warning about what they shadow."""
    if not extra:
        return series

    warned: set[str] = set()
    for name in sorted(extra.keys() & {key for one in series for key in one.labels}):
        if name not in warned:
            print(
                f"warning: --extra-labels {name}=... overrides the benchmark "
                f"parameter named {name!r}",
                file=sys.stderr,
            )
            warned.add(name)

    return [one._replace(labels={**one.labels, **extra}) for one in series]


def deduplicate(series: list[Series]) -> list[Series]:
    """Drop series whose identity was already seen.

    OpenMetrics forbids repeating a label set within a metric family, which is
    otherwise easy to trip over by passing the same results twice (say a
    directory and one of the files inside it).
    """
    seen: set[tuple[tuple[str, str], ...]] = set()
    unique: list[Series] = []
    for one in series:
        key = tuple(sorted(one.labels.items()))
        if key in seen:
            print(
                "warning: skipping duplicate result for "
                f"{one.labels.get('benchmark')} ({one.labels.get('mode')})",
                file=sys.stderr,
            )
            continue
        seen.add(key)
        unique.append(one)
    return unique


def family(
    name: str, help_text: str, samples: Iterable[tuple[dict[str, str], float]]
) -> list[str]:
    """Render one metric family, omitting it entirely if it has no readings."""
    rendered = [
        sample(name, labels, value)
        for labels, value in samples
        # A family that nothing reported is better left out than filled with
        # NaN: it lets one exposition carry both harnesses without inventing
        # measurements neither of them made.
        if value == value
    ]
    if not rendered:
        return []
    return [f"# TYPE {name} gauge", f"# HELP {name} {help_text}", *rendered]


def convert(series: list[Series], extra_labels: dict[str, str] | None = None) -> str:
    series = deduplicate(apply_extra_labels(series, extra_labels or {}))

    families = [
        family(
            SCORE,
            "Primary benchmark metric score.",
            [(one.labels, one.score.value) for one in series],
        ),
        family(
            SCORE_ERROR,
            SCORE_ERROR_HELP,
            [
                ({**one.labels, "confidence": one.confidence}, one.score.error)
                for one in series
            ],
        ),
        family(
            SCORE_PERCENTILE,
            "Primary benchmark metric score percentiles.",
            [
                ({**one.labels, "quantile": quantile}, value)
                for one in series
                for quantile, value in one.percentiles.items()
            ],
        ),
        family(
            SCORE_MEDIAN_DEVIATION,
            "Median absolute deviation of the score, in the score unit.",
            [(one.labels, one.median_deviation) for one in series],
        ),
        family(
            SAMPLES,
            "Number of measurements the benchmark collected.",
            [(one.labels, one.samples) for one in series],
        ),
    ]

    lines = [line for one in families for line in one]
    lines.append("# EOF")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "-f",
        "--format",
        required=True,
        choices=sorted(HARNESSES),
        help="the harness that produced the results",
    )
    parser.add_argument(
        "input",
        nargs="*",
        type=Path,
        help="benchmark results JSON files or directories (default: the output "
        "location of the harness given by --format)",
    )
    parser.add_argument(
        "--extra-labels",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="add this label to every sample; repeat for more than one label "
        "(e.g. --extra-labels target=jvm)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write to this file instead of stdout",
    )
    opts = parser.parse_args(argv)

    harness = HARNESSES[opts.format]
    inputs = opts.input or [harness.default_input]

    try:
        extra_labels = parse_extra_labels(opts.extra_labels)
        series = read_series(inputs, harness)
    except FileNotFoundError as exc:
        parser.error(f"input file not found: {exc.filename}")
    except IsADirectoryError as exc:
        parser.error(f"cannot read directory as a file: {exc.filename}")
    except NotADirectoryError as exc:
        parser.error(f"not a directory: {exc.filename}")
    except json.JSONDecodeError as exc:
        parser.error(f"invalid JSON: {exc}")
    except ValueError as exc:
        parser.error(str(exc))

    exposition = convert(series, extra_labels)

    if opts.output is None:
        sys.stdout.write(exposition)
    else:
        opts.output.write_text(exposition)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
