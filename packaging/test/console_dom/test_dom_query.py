import unittest

from dom_query import query


class DOMQueryTests(unittest.TestCase):
    def test_action_attributes_must_belong_to_same_element(self):
        dom = query('<button data-action="kill" data-pid="42">Kill</button><button data-pid="5821">Other</button>')
        self.assertFalse(dom.has(attrs={"data-action": "kill", "data-pid": "5821"}))
        self.assertTrue(dom.has("button", {"data-action": "kill", "data-pid": "42"}))
