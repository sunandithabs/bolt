from pathlib import Path


class RollbackStore:
    def __init__(self, path: str):
        self.path = Path(path)
        if not self.path.exists():
            self.path.write_text("0")

    def get(self) -> int:
        return int(self.path.read_text().strip())

    def commit(self, index: int):
        if index < self.get():
            raise ValueError("cannot commit lower rollback index")
        self.path.write_text(str(index))
