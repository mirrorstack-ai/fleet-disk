"""Stand-in for the one git boundary the vendored packer imports: an argument list with no shell and the same fixed flags
on every call, so no hook and no fsmonitor command in the repository runs, paths come back unquoted and git never prompts.
Unlike the fleet's own, an error never carries git's stderr: this runs in a public log, where a path name is a leak."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

# under this regular file: absolute and never a directory on every OS, so no hook can exist there
NO_HOOKS = os.path.join(os.path.abspath(__file__), 'no-hooks')
FIXED = ('-c', f'core.hooksPath={NO_HOOKS}', '-c', 'core.fsmonitor=false', '-c', 'core.quotePath=false')
# `git rev-parse --local-env-vars`: what git itself clears before it works in another repository
LOCAL_ENV = ('GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_CONFIG', 'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_COUNT',
             'GIT_OBJECT_DIRECTORY', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_IMPLICIT_WORK_TREE', 'GIT_GRAFT_FILE',
             'GIT_INDEX_FILE', 'GIT_NO_REPLACE_OBJECTS', 'GIT_REPLACE_REF_BASE', 'GIT_PREFIX', 'GIT_SHALLOW_FILE',
             'GIT_COMMON_DIR')


class GitError(RuntimeError):
    """A git call that failed, timed out or could not start; the message names the verb and the exit status only."""


class Git:
    """git in one working directory: `run('cat-file', 'blob', x)` is `git <FIXED> cat-file blob x` there."""

    def __init__(self, cwd: Path, runner=subprocess.run, timeout_s: float = 120.0) -> None:
        self.cwd = Path(cwd)
        self._runner = runner
        self._timeout_s = timeout_s

    def run(self, *args: str, input: bytes | None = None) -> bytes:
        """git's stdout; stdin is input or empty, never the terminal. Raises GitError on any failure."""
        env = {k: v for k, v in os.environ.items() if k not in LOCAL_ENV}
        env['GIT_TERMINAL_PROMPT'] = '0'
        verb = args[0] if args else ''
        try:
            done = self._runner(['git', *FIXED, *args], cwd=self.cwd, input=input or b'', capture_output=True,
                                env=env, timeout=self._timeout_s, check=False)
        except subprocess.TimeoutExpired:
            raise GitError(f'git {verb} timed out') from None
        except OSError:
            raise GitError(f'git {verb} could not start') from None
        if done.returncode != 0:
            raise GitError(f'git {verb} failed (exit {done.returncode})')
        return done.stdout
