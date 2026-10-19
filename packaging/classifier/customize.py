#!/usr/bin/env python3
"""Offline adaptation of an existing local Kev checkpoint for shell review.

No commands from a dataset are executed. Torch/Kev imports occur only for tuning.
Datasets, checkpoints and reports belong outside version control.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import random
import subprocess
import sys
import time


LABELS = ("review", "routine", "unknown")
SPLITS = ("train", "development", "test")
DEFAULT_POLICY = Path(__file__).resolve().parents[2] / "daemon/internal/shellreview/policy.json"


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Synthetic input is still kept private; never relax an existing file's mode.
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def load_policy(path):
    policy = json.loads(Path(path).read_text())
    if set(policy) != {"version", "criteria", "instructions"} or set(policy["criteria"]) != set(LABELS):
        raise ValueError("invalid shell policy")
    if not all(isinstance(x, str) and x for x in [policy["version"], policy["instructions"], *policy["criteria"].values()]):
        raise ValueError("empty shell policy")
    policy["criteria"] = dict(sorted(policy["criteria"].items()))
    return policy


def validate_rows(rows):
    ids, commands, families, counts = set(), set(), {}, Counter()
    for row in rows:
        if set(row) != {"id", "family", "split", "label", "command", "cwd"}:
            raise ValueError("unexpected dataset fields")
        if not all(isinstance(v, str) for v in row.values()):
            raise ValueError("dataset values must be strings")
        if row["split"] not in SPLITS or row["label"] not in LABELS or not row["id"] or not row["family"]:
            raise ValueError("invalid split, label, id or family")
        if not row["command"].strip() or len(row["command"].encode()) > 8192 or len(row["cwd"].encode()) > 4096:
            raise ValueError("invalid command or working directory length")
        if "\0" in row["command"] + row["cwd"]:
            raise ValueError("NUL in dataset")
        if row["id"] in ids or row["command"].strip() in commands:
            raise ValueError("duplicate id or command, including across splits")
        previous = families.setdefault(row["family"], row["split"])
        if previous != row["split"]:
            raise ValueError("command family leaks across splits")
        ids.add(row["id"])
        commands.add(row["command"].strip())
        counts[row["split"], row["label"]] += 1
    if any(counts[s, k] == 0 for s in SPLITS for k in LABELS):
        raise ValueError("each split must contain every label")
    return {s: {k: counts[s, k] for k in LABELS} for s in SPLITS}


def request_for(row, policy):
    return {"state": "Working directory: " + row["cwd"] + "\nShell command:\n" + row["command"],
            "questions": {"risk": {"type": "choice", "criteria": policy["criteria"],
                                   "instructions": policy["instructions"]}}}


def read_rows(path):
    suite = json.loads(Path(path).read_text())
    if set(suite) != {"version", "rows"} or suite["version"] != 1:
        raise ValueError("invalid dataset version")
    validate_rows(suite["rows"])
    return suite["rows"]


def freeze(suite, policy, manifest):
    if Path(manifest).exists():
        raise ValueError("refusing to overwrite frozen manifest")
    rows = read_rows(suite)
    load_policy(policy)
    write_json(manifest, {"version": 1, "suite_sha256": sha256(suite), "policy_sha256": sha256(policy),
                          "counts": validate_rows(rows)})


def load_suite(suite, policy, manifest):
    expected = json.loads(Path(manifest).read_text())
    if expected.get("version") != 1 or expected.get("suite_sha256") != sha256(suite) or expected.get("policy_sha256") != sha256(policy):
        raise ValueError("dataset or policy differs from frozen manifest")
    rows = read_rows(suite)
    if validate_rows(rows) != expected["counts"]:
        raise ValueError("manifest counts mismatch")
    return rows, load_policy(policy)


def summarize(rows, probabilities):
    if not rows or len(rows) != len(probabilities):
        raise ValueError("incomplete evaluation")
    counts = Counter()
    by_label = {k: Counter() for k in LABELS}
    observations = []
    for row, raw in zip(rows, probabilities):
        if set(raw) != set(LABELS) or any(not math.isfinite(p) or not 0 <= p <= 1 for p in raw.values()) or abs(sum(raw.values()) - 1) > .0001:
            raise ValueError("invalid model distribution")
        choice = max(LABELS, key=lambda k: raw[k])
        # Kev serializes each score to two decimal places. The daemon gates on
        # that serialized probability; measuring raw logits understates risk.
        allowed = choice == "routine" and round(raw["routine"], 2) >= .9
        item = {"n": 1, "correct": int(choice == row["label"]),
                "false_routine": int(allowed and row["label"] != "routine"),
                "routine_allowed": int(allowed and row["label"] == "routine"),
                "abstained": int(choice == "routine" and not allowed)}
        counts.update(item)
        by_label[row["label"]].update(item)
        observations.append({"id": row["id"], "expected": row["label"], "choice": choice,
                             "would_allow": allowed, "probabilities": raw})
    return {**counts, "accuracy": counts["correct"] / counts["n"],
            "by_label": {k: dict(v) for k, v in by_label.items()}, "observations": observations}


def selection_key(metrics):
    # Development data selects a candidate; the locked test never selects one.
    return (-metrics["false_routine"], metrics["correct"], metrics["routine_allowed"])


def assessment(baseline, candidate):
    """Reject observed false allows and regressions; passing is not authorization."""
    if baseline["n"] != candidate["n"] or baseline["n"] < 1:
        raise ValueError("comparisons require identical nonempty test sets")
    failures = []
    if candidate["false_routine"]:
        failures.append("non_routine_commands_allowed")
    if candidate["correct"] < baseline["correct"]:
        failures.append("label_accuracy_regressed")
    if candidate["routine_allowed"] < baseline["routine_allowed"]:
        failures.append("routine_coverage_regressed")
    return failures


def tune(args):
    # Keep the source repository and the live checkpoint read-only. Offline mode
    # forbids implicit base-weight downloads or external data transfer.
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    rows, policy = load_suite(args.suite, args.policy, args.manifest)
    source = Path(args.kev_source).resolve(strict=True)
    checkpoint = Path(args.checkpoint).resolve(strict=True)
    out = Path(args.out).resolve()
    if out.exists():
        raise ValueError("refusing to overwrite an existing run")
    if checkpoint == out or checkpoint in out.parents or source == out or source in out.parents:
        raise ValueError("output must be separate from Kev source and input checkpoint")
    for name in ("adapter_config.json", "adapter_model.safetensors", "head.pt"):
        if not (checkpoint / name).is_file():
            raise ValueError("checkpoint is missing " + name)
    sys.path.insert(0, str(source))
    import torch
    import torch.nn.functional as functional
    from peft import PeftModel, set_peft_model_state_dict
    from safetensors.torch import load_file
    from kev.api import SystemOneRequest, to_record
    from kev.model import DecisionModel, load_tokenizer

    torch.manual_seed(args.seed)
    torch.set_num_threads(4)
    rng = random.Random(args.seed)
    device = "mps" if torch.backends.mps.is_available() else "cpu"
    meta = torch.load(checkpoint / "head.pt", map_location="cpu", weights_only=False)
    if not meta.get("base_revision"):
        raise ValueError("checkpoint must pin its base revision")
    tok = load_tokenizer(meta["base"], revision=meta["base_revision"])
    model = DecisionModel(meta["base"], tok, device, revision=meta["base_revision"],
                          head_dim=meta.get("head_dim", 256), option_isolation=meta.get("option_isolation", False), attn="sdpa")
    model.lm = PeftModel.from_pretrained(model.lm, str(checkpoint), is_trainable=True).to(device)
    model.head.load_state_dict(meta["head"])
    model.lm.config.use_cache = False
    encoded = {}
    for row in rows:
        rec, _ = to_record(SystemOneRequest(**request_for(row, policy)))
        rec["questions"][0]["label"] = LABELS.index(row["label"])
        encoded[row["id"]] = model.encode(tok, rec, strict=True)
    partitions = {s: [r for r in rows if r["split"] == s] for s in SPLITS}
    provenance = {"version": 1, "suite_sha256": sha256(args.suite), "policy_sha256": sha256(args.policy),
                  "trainer_sha256": sha256(__file__),
                  "checkpoint_sha256": {n: sha256(checkpoint / n) for n in ("adapter_config.json", "adapter_model.safetensors", "head.pt")},
                  "base": meta["base"], "base_revision": meta["base_revision"], "policy_version": policy["version"],
                  "kev_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip(),
                  "kev_source_sha256": {name: sha256(source / "kev" / name) for name in ("api.py", "model.py")},
                  "seed": args.seed, "epochs": args.epochs, "lr": args.lr, "accum": args.accum, "device": device,
                  "torch": torch.__version__, "gate_routine_probability": .9,
                  "counts": validate_rows(rows), "evaluation_scope": "synthetic shell commands"}
    out.mkdir(parents=True, mode=0o700)
    write_json(out / "provenance.json", provenance)

    def evaluate(split):
        model.eval()
        with torch.no_grad():
            ps = [dict(zip(LABELS, model.probs(encoded[r["id"]])[0].tolist())) for r in partitions[split]]
        return summarize(partitions[split], ps)

    def brief(name, metrics):
        print(json.dumps({"stage": name, **{k: v for k, v in metrics.items() if k != "observations"}}), flush=True)

    baseline_dev = evaluate("development")
    write_json(out / "baseline-development.json", baseline_dev)
    brief("baseline-development", baseline_dev)
    best, best_epoch = None, None
    parameters = model.trainable_parameters()
    optimizer = torch.optim.AdamW(parameters, lr=args.lr, weight_decay=.01)
    train = list(partitions["train"])
    started, seen = time.monotonic(), 0
    for epoch in range(1, args.epochs + 1):
        model.train()
        rng.shuffle(train)
        optimizer.zero_grad(set_to_none=True)
        loss_sum = 0.
        for i, row in enumerate(train):
            z = model.forward_batch([encoded[row["id"]]])[0][0]
            loss = functional.cross_entropy(z.float()[None], torch.tensor([LABELS.index(row["label"])], device=device))
            if not torch.isfinite(loss):
                raise ValueError("non-finite training loss")
            group_size = min(args.accum, len(train) - (i // args.accum) * args.accum)
            (loss / group_size).backward()
            loss_sum += loss.item()
            seen += 1
            if (i + 1) % args.accum == 0 or i + 1 == len(train):
                torch.nn.utils.clip_grad_norm_(parameters, 1.)
                optimizer.step()
                optimizer.zero_grad(set_to_none=True)
                if device == "mps":
                    torch.mps.empty_cache()
            if (i + 1) % 20 == 0 or i == 0:
                print(json.dumps({"stage": "training", "epoch": epoch, "record": i + 1, "of": len(train),
                                  "loss": loss_sum / (i + 1), "seconds_per_record": (time.monotonic() - started) / seen}), flush=True)
        metrics = evaluate("development")
        write_json(out / f"epoch-{epoch}-development.json", metrics)
        brief(f"epoch-{epoch}-development", metrics)
        if best is None or selection_key(metrics) > selection_key(best):
            best, best_epoch = metrics, epoch
            candidate = out / "candidate"
            model.lm.save_pretrained(candidate)
            torch.save({**meta, "head": model.head.state_dict()}, candidate / "head.pt")
            tok.save_pretrained(candidate)
    # Fix the candidate before scoring the locked test. Neither its examples nor
    # its labels were passed to the optimizer or the candidate selection rule.
    set_peft_model_state_dict(model.lm, load_file(str(out / "candidate/adapter_model.safetensors")))
    model.head.load_state_dict(torch.load(out / "candidate/head.pt", map_location="cpu", weights_only=False)["head"])
    candidate_test = evaluate("test")
    set_peft_model_state_dict(model.lm, load_file(str(checkpoint / "adapter_model.safetensors")))
    model.head.load_state_dict(meta["head"])
    baseline_test = evaluate("test")
    failures = assessment(baseline_test, candidate_test)
    report = {"provenance": provenance, "selected_epoch": best_epoch, "wall_seconds": time.monotonic() - started,
              "baseline": baseline_test, "candidate": candidate_test, "rejection_reasons": failures}
    write_json(out / "comparison.json", report)
    write_json(out / "candidate/training_config.json", provenance)
    write_json(out / "candidate/shell-customization.json", {**provenance, "selected_epoch": best_epoch,
                                                           "status": "rejected" if failures else "experimental; synthetic evaluation only",
                                                           "rejection_reasons": failures})
    brief("baseline-test", baseline_test)
    brief("candidate-test", candidate_test)
    print(json.dumps({"stage": "assessment", "rejection_reasons": failures}), flush=True)
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("freeze", "tune"))
    parser.add_argument("--suite", required=True)
    parser.add_argument("--policy", default=str(DEFAULT_POLICY))
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--kev-source")
    parser.add_argument("--checkpoint")
    parser.add_argument("--out")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--accum", type=int, default=4)
    parser.add_argument("--seed", type=int, default=23)
    args = parser.parse_args()
    if args.action == "freeze":
        freeze(args.suite, args.policy, args.manifest)
    else:
        if not all((args.kev_source, args.checkpoint, args.out)) or min(args.epochs, args.accum) < 1 or not math.isfinite(args.lr) or args.lr <= 0:
            parser.error("tuning requires source, checkpoint, out and positive training settings")
        if tune(args):
            raise SystemExit(2)


if __name__ == "__main__":
    main()
