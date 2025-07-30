from marscan.scanner.stealth import StealthScan

class XmasScan(StealthScan):
    """
    Performs a TCP XMAS scan by sending a TCP packet with the FIN, PSH, and URG flags set.
    Inherits the core stealth scanning logic from the StealthScan base class.
    """
    flags = "FPU"
