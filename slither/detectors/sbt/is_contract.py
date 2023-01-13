from collections import defaultdict

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.solidity_types.elementary_type import ElementaryType

class UnsafeIsContractCheck(AbstractDetector):
    """
    Unsafe check for checking if caller is Contract
    """

    ARGUMENT = 'is_contract_check' # slither will launch the detector with slither.py --detect mydetector
    HELP = 'Hackable check if caller is a Contract or EOA'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'link catre descriere'

    WIKI_TITLE = 'Hackable check if caller is a Contract or EOA'
    WIKI_DESCRIPTION = 'The use of extcodesize is hackable. If a contract will call the function with that check from its constructor, extcodesize will return 0 and the cehck will be passed.'
    WIKI_EXPLOIT_SCENARIO = 'Call the function with the check from a contract constructor'
    WIKI_RECOMMENDATION = 'Do not use extcodesize for important functions. Instead use msg.sender == tx.origin'


    @staticmethod
    def detect_extcodesize(nodes):
        var_nodes = []
        for node in nodes:
            if str(node).__contains__("extcodesize"):
                for son in node.sons:
                    if son.is_conditional():
                        var_nodes.append(node)
        return var_nodes

    def _detect(self):
        """Detect the functions that use extcodesize to check if an address is Contract or EAO"""
        results = []
        for contract in self.contracts:
            for f in contract.functions:
                if f.contract_declarer != contract:
                 continue
                nodes = f.nodes
                info = [f, ' uses extcodesize\n']
                extcodesize_nodes = self.detect_extcodesize(nodes)
            
                # de verificat si cu openzeppelin
                for n in extcodesize_nodes:
                    info += ["\t- ", n, "\n"]
                res = self.generate_result(info)
                results.append(res)
        return results

