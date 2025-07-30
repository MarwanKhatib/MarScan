from marscan.scanner.stealth import StealthScan

class NullScan(StealthScan):
    """
    Performs a TCP NULL scan by sending a TCP packet with no flags set.
    Inherits the core stealth scanning logic from the StealthScan base class.
    """
    flags = ""
