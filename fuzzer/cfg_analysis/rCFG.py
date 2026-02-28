from cfg_analysis.cfg.disassembly import generate_BBs
from cfg_analysis.cfg.cfg import CFG

class rCFG(object):

    def __init__(self, bytecode):
        self.bytecode = bytecode
        self.code = bytes.fromhex(bytecode)
        self.bbs = None
        self.cfg = None

    def build_cfg(self):
        self.bbs = list(generate_BBs(self.code))
        self.cfg = CFG(self.bbs, fix_xrefs=True)

        return self.cfg

    def get_cfg(self):
        if self.cfg is None:
            self.build_cfg()
        return self.cfg

