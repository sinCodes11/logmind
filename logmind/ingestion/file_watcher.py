"""File-based log ingestion with tail-like behavior."""

import asyncio
from pathlib import Path
from typing import AsyncIterator, Callable

import aiofiles

from logmind.ingestion.base import BaseParser, NormalizedLog


class FileWatcher:
    """
    Watch log files and yield new lines as they are appended.

    Supports:
    - Single file monitoring
    - Directory monitoring with glob patterns
    - File rotation detection
    """

    def __init__(
        self,
        parser: BaseParser,
        poll_interval: float = 0.5,
    ) -> None:
        """
        Initialize file watcher.

        Args:
            parser: Parser to use for log lines
            poll_interval: Seconds between file checks
        """
        self.parser = parser
        self.poll_interval = poll_interval
        self._file_positions: dict[Path, int] = {}
        self._running = False

    async def read_file(
        self,
        file_path: str | Path,
        from_beginning: bool = True,
        max_file_size: int = 100 * 1024 * 1024,  # 100MB default
    ) -> list[NormalizedLog]:
        """
        Read and parse an entire log file.

        Args:
            file_path: Path to log file
            from_beginning: If True, read from start; if False, only new lines
            max_file_size: Maximum file size in bytes (DoS protection)

        Returns:
            List of parsed NormalizedLog entries
        """
        path = Path(file_path).resolve()

        # Security validations
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        if not path.is_file():
            raise ValueError(f"Path is not a regular file: {path}")

        # Check file size to prevent DoS
        file_size = path.stat().st_size
        if file_size > max_file_size:
            raise ValueError(f"File too large: {file_size} bytes (max {max_file_size})")

        source = path.name
        logs = []

        async with aiofiles.open(path, "r", encoding="utf-8", errors="replace") as f:
            if not from_beginning and path in self._file_positions:
                await f.seek(self._file_positions[path])

            content = await f.read()
            self._file_positions[path] = await f.tell()

        for line in content.splitlines():
            line = line.strip()
            if line:
                parsed = self.parser.parse(line, source)
                if parsed:
                    logs.append(parsed)

        return logs

    async def tail_file(
        self,
        file_path: str | Path,
        callback: Callable[[NormalizedLog], None] | None = None,
    ) -> AsyncIterator[NormalizedLog]:
        """
        Tail a log file, yielding new lines as they are written.

        Args:
            file_path: Path to log file
            callback: Optional callback for each parsed log

        Yields:
            NormalizedLog entries as they are appended
        """
        path = Path(file_path).resolve()

        # Security validations
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        if not path.is_file():
            raise ValueError(f"Path is not a regular file: {path}")

        source = path.name
        self._running = True

        async with aiofiles.open(path, "r", encoding="utf-8", errors="replace") as f:
            await f.seek(0, 2)
            self._file_positions[path] = await f.tell()
            last_inode = path.stat().st_ino

            while self._running:
                try:
                    current_inode = path.stat().st_ino
                    if current_inode != last_inode:
                        await f.seek(0)
                        self._file_positions[path] = 0
                        last_inode = current_inode
                except FileNotFoundError:
                    await asyncio.sleep(self.poll_interval)
                    continue

                line = await f.readline()
                if line:
                    line = line.strip()
                    if line:
                        parsed = self.parser.parse(line, source)
                        if parsed:
                            if callback:
                                callback(parsed)
                            yield parsed
                else:
                    await asyncio.sleep(self.poll_interval)

    def stop(self) -> None:
        """Stop tailing files."""
        self._running = False

    async def watch_directory(
        self,
        directory: str | Path,
        pattern: str = "*.log",
        callback: Callable[[NormalizedLog], None] | None = None,
    ) -> AsyncIterator[NormalizedLog]:
        """
        Watch a directory for log files matching a pattern.

        Args:
            directory: Directory to watch
            pattern: Glob pattern for log files
            callback: Optional callback for each parsed log

        Yields:
            NormalizedLog entries from matching files
        """
        dir_path = Path(directory)
        if not dir_path.is_dir():
            raise NotADirectoryError(f"Not a directory: {dir_path}")

        self._running = True
        tasks: dict[Path, asyncio.Task] = {}
        queues: dict[Path, asyncio.Queue] = {}

        async def file_producer(file_path: Path, queue: asyncio.Queue):
            """Produce logs from a single file to a queue."""
            async for log in self.tail_file(file_path, callback):
                await queue.put(log)

        while self._running:
            current_files = set(dir_path.glob(pattern))

            for file_path in current_files - set(tasks.keys()):
                queue: asyncio.Queue = asyncio.Queue()
                queues[file_path] = queue
                tasks[file_path] = asyncio.create_task(file_producer(file_path, queue))

            for file_path in set(tasks.keys()) - current_files:
                tasks[file_path].cancel()
                del tasks[file_path]
                del queues[file_path]

            for queue in queues.values():
                try:
                    while True:
                        log = queue.get_nowait()
                        yield log
                except asyncio.QueueEmpty:
                    pass

            await asyncio.sleep(self.poll_interval)

        for task in tasks.values():
            task.cancel()
