from .nmap import NmapParser
from .certipy import CertipyParser
from .netexec import NetExecParser
from .bloodhound import BloodHoundParser
from .privesc import PrivescParser
from .ad import ADParser
from .cloud import CloudParser
from .container import ContainerParser
from .cicd import CICDParser
from .generic import GenericParser

_PARSERS = [
    NmapParser(), CertipyParser(), NetExecParser(), BloodHoundParser(),
    ADParser(), CloudParser(), ContainerParser(), CICDParser(),
    PrivescParser(), GenericParser(),
]


def auto_parse(text: str) -> dict:
    best_parser = None
    best_conf = 0.0
    for p in _PARSERS:
        try:
            c = p.confidence(text)
            if c > best_conf:
                best_conf = c
                best_parser = p
        except Exception:
            continue
    if best_parser is None:
        best_parser = GenericParser()
        best_conf = 0.1
    try:
        result = best_parser.parse(text)
    except Exception as e:
        result = {"hosts": [], "credentials": [], "findings": []}
    return {"parser": best_parser.name, "confidence": round(best_conf, 2), **result}
