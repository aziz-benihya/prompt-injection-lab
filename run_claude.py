"""Optional: run the attack scenarios against a real Claude model.

    pip install anthropic
    export ANTHROPIC_API_KEY=...        # or: ant auth login
    python run_claude.py --limit 5      # costs API credits

Compares "spotlighting only" (no code-level defense) with the full stack.
"""

import argparse

from lab.agent import Config
from lab.claude_llm import MODEL, run_with_claude
from lab.environment import Environment
from lab.evaluation import attack_succeeded, task_completed
from lab.scenarios import CONFIDENTIAL, build


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=5, help="scenarios per kind (attack/benign)")
    args = parser.parse_args()

    scenarios = build()
    picked = [s for s in scenarios if s.kind == "attack"][: args.limit] + \
             [s for s in scenarios if s.kind == "benign"][: args.limit]

    for cfg in [Config("spotlighting only"), Config("spotlighting + D1 + D2 + D3", True, True, True)]:
        hit = ok = 0
        for sc in picked:
            env = Environment(dict(sc.documents), confidential=set(CONFIDENTIAL))
            run_with_claude(env, sc.task, cfg)
            if sc.kind == "attack":
                hit += attack_succeeded(env)
            else:
                ok += task_completed(env, sc.doc_name)
        print(f"[{MODEL}] {cfg.name}: attacks succeeded {hit}/{args.limit}, benign completed {ok}/{args.limit}")


if __name__ == "__main__":
    main()
