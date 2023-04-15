"""
Utility class used to keep track of parameters to maintain for 
each function in the output ground truth dataset.
"""
class params:
    fields = ['static', 'inst_pos_emb', 'op_pos_emb', 'arch_emb', 'byte1', 'byte2', 'byte3', 'byte4', 'label']
    context_fields = fields[:-1]
    dummy_sequence = {
        'x64': {'static': ',', 'inst_pos_emb': '0', 'op_pos_emb': '0', 'arch_emb': 'x64', 'byte1': '##', 'byte2': '##', 'byte3': '##', 'byte4': '##'},
        'x86': {'static': ',', 'inst_pos_emb': '0', 'op_pos_emb': '0', 'arch_emb': 'x86', 'byte1': '##', 'byte2': '##', 'byte3': '##', 'byte4': '##'},
        'arm': {'static': ',', 'inst_pos_emb': '0', 'op_pos_emb': '0', 'arch_emb': 'arm', 'byte1': '##', 'byte2': '##', 'byte3': '##', 'byte4': '##'},
        'mips': {'static': ',', 'inst_pos_emb': '0', 'op_pos_emb': '0', 'arch_emb': 'mips', 'byte1': '##', 'byte2': '##', 'byte3': '##', 'byte4': '##'},
    }
