from marscan.scanner.stealth import StealthScan

class FinScan(StealthScan):
    """
    Performs a TCP FIN scan by sending a TCP packet with only the FIN flag set.
    Inherits the core stealth scanning logic from the StealthScan base class.
    """
    flags = "F"
