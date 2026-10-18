import copy
import unittest
from tools.inspect_transfer_dependencies import inspect_index


def fixture():
    # Original dataflow fixture: direct call result feeds an indirect transfer.
    return {'nodes':[
        {'id':0,'constant':False,'definition':None},
        {'id':1,'constant':False,'definition':0},
        {'id':2,'constant':True,'definition':None}],
        'operations':[
            {'id':0,'site':'10','opcode':'CALL','inputs':[0],'output':1},
            {'id':1,'site':'20','opcode':'CALLIND','inputs':[1],'output':None},
            {'id':2,'site':'30','opcode':'RETURN','inputs':[2,1],'output':None}]}


class TransferDependencyTests(unittest.TestCase):
    def test_direct_callee_address_is_not_an_unbound_return_value(self):
        rows,_=inspect_index(fixture(),{'20'})
        self.assertEqual(rows[0]['direct_callee_return_boundaries'],1)
        self.assertEqual(rows[0]['unbound_input_leaves'],0)
        self.assertFalse(rows[0]['resolved_constant_root'])

    def test_return_uses_value_not_return_destination(self):
        rows,_=inspect_index(fixture(),set(),mode='returns')
        self.assertEqual(len(rows),1)
        self.assertFalse(rows[0]['root_is_constant'])
        self.assertEqual(rows[0]['call_return_boundaries'],1)

    def test_memory_read_is_unknown_even_at_constant_address(self):
        data=fixture();data['operations'][0].update(opcode='LOAD',inputs=[2,2])
        rows,_=inspect_index(data,{'20'})
        self.assertEqual(rows[0]['memory_value_boundaries'],1)
        self.assertEqual(rows[0]['dynamic_address_memory_reads'],0)
        self.assertFalse(rows[0]['resolved_constant_root'])

    def test_budget_and_missing_site_are_explicit(self):
        rows,_=inspect_index(fixture(),{'20'},node_limit=0)
        self.assertTrue(rows[0]['budget_exhausted'])
        self.assertEqual(inspect_index(fixture(),{'absent'}),([],[]))

    def test_malformed_links_are_rejected(self):
        original=fixture()
        for mutation in ('duplicate','dangling','definition'):
            data=copy.deepcopy(original)
            if mutation=='duplicate':data['nodes'].append(data['nodes'][0])
            elif mutation=='dangling':data['operations'][0]['inputs']=[100]
            else:data['nodes'][1]['definition']=100
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                inspect_index(data,{'20'})

    def test_call_arguments_exclude_callee_identity(self):
        data=fixture();data['operations'][0]['inputs']=[0,2,0]
        rows,_=inspect_index(data,{'10'},mode='call-arguments')
        self.assertEqual(len(rows),2)
        self.assertTrue(rows[0]['root_is_constant'])
        self.assertEqual(rows[1]['unbound_input_leaves'],1)
