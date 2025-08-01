"""
Console utilities for FRAITMO with verbosity control
"""

from rich.console import Console
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn


class VerboseConsole:
    """Console wrapper that respects verbosity settings"""

    def __init__(self, verbose: bool = False, quiet: bool = False):
        self.console = Console()
        self.verbose = verbose
        self.quiet = quiet
        self.progress = None
        self.current_task = None

    def print(self, *args, **kwargs):
        """Print only if verbose or if it's an error/result"""
        if self.quiet:
            # Only show errors in quiet mode
            if args and len(args) > 0:
                first_arg = str(args[0])
                if "[ERROR]" in first_arg:
                    self.console.print(*args, **kwargs)
            return

        if self.verbose:
            # Show everything in verbose mode
            self.console.print(*args, **kwargs)
        else:
            # In normal mode, show ONLY essential final results
            if args and len(args) > 0:
                first_arg = str(args[0])

                # Only allow these FINAL result messages in normal mode
                allowed_final_messages = [
                    "[ERROR]",  # Always show errors
                    "[OK] FRAITMO Analysis Complete!",
                    "[INFO] Overall Risk:",
                    "[INFO] Total Threats Found:",
                    "[OK] Analysis complete:",
                    "[INFO] ANALYSIS SUMMARY:",
                    "[OK] FRAITMO THREAT ANALYSIS RESULTS"
                ]
                
                # Block verbose-only messages in normal mode
                verbose_only_messages = [
                    "threat coverage:",
                    "Coverage insufficient:",
                    "complexity score:",
                    "allocated tokens:",
                    "Added",
                    "additional",
                    "Recovered",
                    "threats from malformed",
                    "Enhanced",
                    "Deduplication",
                    "Quality filter",
                    "[DEBUG]",
                    "[WARN]",  # Coverage warnings should be verbose-only
                    "enhancement"
                ]
                
                # Block verbose-only messages unless they're errors
                if not "[ERROR]" in first_arg and any(msg in first_arg for msg in verbose_only_messages):
                    return

                # Block ALL other messages in normal mode
                if any(msg in first_arg for msg in allowed_final_messages):
                    self.console.print(*args, **kwargs)

    def start_progress(self, description: str):
        """Start progress tracking"""
        if not self.verbose and not self.quiet:
            self.progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=self.console
            )
            self.progress.start()
            self.current_task = self.progress.add_task(description, total=100)

    def update_progress(self, progress_percent: int, description: str = None):
        """Update progress to absolute percentage"""
        if self.progress and self.current_task is not None:
            if description:
                self.progress.update(self.current_task, description=description)
            # Set absolute progress instead of advancing
            current_progress = self.progress.tasks[self.current_task].completed
            advance_amount = max(0, progress_percent - current_progress)
            if advance_amount > 0:
                self.progress.advance(self.current_task, advance_amount)

    def stop_progress(self):
        """Stop progress tracking"""
        if self.progress:
            self.progress.stop()
            self.progress = None
            self.current_task = None
    
    def print_verbose(self, *args, **kwargs):
        """Print only if verbose mode is enabled"""
        if self.verbose and not self.quiet:
            self.console.print(*args, **kwargs)
    
    def print_debug(self, *args, **kwargs):
        """Print debug messages only in verbose mode"""
        if self.verbose and not self.quiet:
            self.console.print(*args, **kwargs)
    
    def print_coverage(self, message_type: str, message: str):
        """Print coverage validation messages only in verbose mode"""
        if self.verbose and not self.quiet:
            if message_type == "excellent":
                self.console.print(Text("[OK]", style="bold green"), message)
            elif message_type == "good":
                self.console.print(Text("[OK]", style="bold blue"), message)
            elif message_type == "acceptable":
                self.console.print(Text("[INFO]", style="bold cyan"), message)
            elif message_type == "low":
                self.console.print(Text("[WARN]", style="bold yellow"), message)
        # Always show critical coverage errors
        elif message_type == "error":
            self.console.print(Text("[ERROR]", style="bold red"), message)


# Create a default console instance
console = VerboseConsole()

def set_console_verbosity(verbose: bool = False, quiet: bool = False):
    """Set verbosity settings for the global console"""
    global console
    console.verbose = verbose
    console.quiet = quiet
