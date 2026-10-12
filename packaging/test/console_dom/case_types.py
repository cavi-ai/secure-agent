"""The browser case contract."""
from dataclasses import dataclass
from typing import Callable

@dataclass(frozen=True)
class Case:
    name: str
    run: Callable
    fixtures: tuple[str, ...] = ()


@dataclass(frozen=True)
class Fixture:
    query: str = ""
    scenarios: tuple[str, ...] = ()
    payload: Callable | None = None
    served: bool = False
    window_size: tuple[int, int] | None = None
    reduced_motion: bool = False
    script: str = ""

    def load(self, page):
        payload = self.payload() if self.payload else {}
        return page.dom(
            self.query,
            served=self.served,
            window_size=self.window_size,
            reduced_motion=self.reduced_motion,
            fixture={"scenarios": list(self.scenarios), "script": self.script, **payload},
        )
