"""Original x86 graph fixture: two reachable calls and one unreachable call."""
import struct

def fixture_bytes(indirect=False,call_return=False):
    # entry frame, compare [ebp+8] with zero, conditional branch to second call.
    data=bytes.fromhex('55 89 e5 83 7d 08 00 74 07')
    shift=2 if indirect else 0
    data+=b'\xe8'+struct.pack('<i',30+shift-14)
    data+=bytes.fromhex('eb 05')           # offset 14 -> epilogue at 21
    data+=b'\xe8'+struct.pack('<i',33+shift-21)
    # Alternate graph ends in a dynamic memory load then indirect jump.
    data+=bytes.fromhex(('ff d0 ff e0' if call_return else '8b 01 ff e0') if indirect else 'c9 c3')
    data+=b'\xe8'+struct.pack('<i',30-28)
    data+=bytes.fromhex('c3 90 c2 08 00 c2 0c 00')
    return data+bytes(96-len(data))

def fixture_request(indirect=False):
    base=0x020f32ed
    shift=2 if indirect else 0
    return {'entry_va':base,'section':'ram','references':[
        {'candidate_id':1,'source_va':base+9,'target_va':base+30+shift},
        {'candidate_id':2,'source_va':base+16,'target_va':base+33+shift},
        {'candidate_id':1,'source_va':base+23+shift,'target_va':base+30+shift}]}
