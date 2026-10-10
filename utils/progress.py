"""
Progress bar utility for long operations
"""
import sys
import time

class ProgressBar:
    """Simple progress bar for console"""
    
    def __init__(self, total, prefix='Progress:', suffix='', length=50, fill='█'):
        self.total = total
        self.prefix = prefix
        self.suffix = suffix
        self.length = length
        self.fill = fill
        self.current = 0
        self.start_time = time.time()
    
    def update(self, current=None):
        """Update progress bar"""
        if current is not None:
            self.current = current
        else:
            self.current += 1
        
        percent = self.current / self.total
        filled_length = int(self.length * percent)
        bar = self.fill * filled_length + '-' * (self.length - filled_length)
        
        # Calculate ETA
        if self.current > 0:
            elapsed = time.time() - self.start_time
            eta = (elapsed / self.current) * (self.total - self.current)
            eta_str = f"ETA: {eta:.1f}s"
        else:
            eta_str = "ETA: --"
        
        sys.stdout.write(f'\r{self.prefix} |{bar}| {percent:.1%} {eta_str} {self.suffix}')
        sys.stdout.flush()
        
        if self.current >= self.total:
            print()
    
    def finish(self):
        """Complete the progress bar"""
        self.update(self.total)
