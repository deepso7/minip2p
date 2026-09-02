import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]


class AwsBenchCleanupTest(unittest.TestCase):
    def run_destroy(self, aws_script: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bin"
            binary.mkdir()
            calls = root / "calls"
            task_arn = root / "task-arn"
            task_arn.write_text("arn:aws:ecs:region:account:task/cluster/task\n")
            for name, script in {
                "aws": aws_script,
                "alchemy": (
                    '#!/usr/bin/env bash\n'
                    ': "${BENCH_DOCKER_CONTEXT:?alchemy.run.ts requires a context}"\n'
                    'printf "alchemy %s\\n" "$*" >> "$CALLS"\n'
                ),
            }.items():
                path = binary / name
                path.write_text(textwrap.dedent(script))
                path.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": f"{binary}:{os.environ['PATH']}",
                "CALLS": str(calls),
                "BENCH_CLUSTER": "test-cluster",
                "BENCH_STAGE": "test-stage",
                "BENCH_TASK_ARN_FILE": str(task_arn),
            }
            result = subprocess.run(
                ["bash", str(ROOT / "infra/bench/destroy.sh")],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            logged = calls.read_text().splitlines() if calls.exists() else []
            return result, logged

    def test_waits_for_tracked_stopping_task_before_destroy(self):
        result, calls = self.run_destroy(
            """\
            #!/usr/bin/env bash
            printf 'aws %s\n' "$*" >> "$CALLS"
            case "$1 $2" in
              'ecs describe-clusters') printf 'ACTIVE\n' ;;
              'ecs list-tasks') printf 'None\n' ;;
              'ecs describe-tasks') printf 'STOPPING\n' ;;
            esac
            """
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        stop = next(index for index, call in enumerate(calls) if "stop-task" in call)
        wait = next(index for index, call in enumerate(calls) if "wait tasks-stopped" in call)
        destroy = next(index for index, call in enumerate(calls) if call.startswith("alchemy "))
        self.assertLess(stop, wait)
        self.assertLess(wait, destroy)

    def test_refuses_destroy_when_task_state_cannot_be_confirmed(self):
        result, calls = self.run_destroy(
            """\
            #!/usr/bin/env bash
            printf 'aws %s\n' "$*" >> "$CALLS"
            exit 1
            """
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sum("describe-clusters" in call for call in calls), 3)
        self.assertFalse(any(call.startswith("alchemy ") for call in calls))

    def test_does_not_repeat_the_long_task_wait(self):
        result, calls = self.run_destroy(
            """\
            #!/usr/bin/env bash
            printf 'aws %s\n' "$*" >> "$CALLS"
            case "$1 $2" in
              'ecs describe-clusters') printf 'ACTIVE\n' ;;
              'ecs list-tasks') printf 'None\n' ;;
              'ecs describe-tasks') printf 'STOPPING\n' ;;
              'ecs wait') exit 1 ;;
            esac
            """
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sum("wait tasks-stopped" in call for call in calls), 1)
        self.assertFalse(any(call.startswith("alchemy ") for call in calls))


if __name__ == "__main__":
    unittest.main()
