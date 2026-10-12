import unittest

from dom_query import query, starts_with


class DOMQueryTests(unittest.TestCase):
    def test_attribute_presence_and_prefix_are_distinct_from_exact_values(self):
        dom = '<svg><polyline points="1,2 3,4"></polyline></svg><div data-key="codex|keychain|host"></div>'
        self.assertTrue(query(dom).has("polyline", {"points": None}))
        self.assertFalse(query(dom).has("polyline", {"points": ""}))
        self.assertTrue(query(dom).has(attrs={"data-key": starts_with("codex|keychain|")}))
        self.assertFalse(query(dom).has(attrs={"data-key": "codex|keychain|"}))

    def test_action_attributes_must_belong_to_same_element(self):
        dom = '<button data-action="kill" data-pid="42">Kill</button><button data-pid="5821">Other</button>'
        self.assertFalse(query(dom).has(attrs={"data-action": "kill", "data-pid": "5821"}))
        self.assertTrue(query(dom).has("button", {"data-action": "kill", "data-pid": "42"}))

    def test_queries_ignore_fake_markup_in_comments_and_scripts(self):
        dom = '<!-- <li class="log-row">fake</li> --><script>"<li class=\"log-row\">fake</li>"</script><li class="fresh log-row" data-row-key="flag:one">A &amp; B<br>old</li>'
        rows = query(dom).find_all("li", {"class": "log-row"})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].attrs["data-row-key"], "flag:one")
        self.assertEqual(rows[0].text, "A & Bold")

    def test_sections_do_not_include_neighbors(self):
        dom = '<section id="one"><p>First</p></section><section id="two">Second</section>'
        node = query(dom).find(attrs={"id": "one"})
        self.assertEqual(node.inner_html, '<p>First</p>')
        self.assertNotIn("Second", node.text)

    def test_text_excludes_evidence_subtrees_without_hiding_sibling_text(self):
        dom = '<li><p>PID 42 outside</p><details><summary>Evidence</summary><div>PID 99<details>nested evidence</details></div></details><p>A &amp; B</p><!-- hidden --><script>fake text</script><style>fake style</style></li>'
        row = query(dom).find('li')
        self.assertEqual(row.text_without('details'), 'PID 42 outsideA & B')
        self.assertEqual(row.text, 'PID 42 outsideEvidencePID 99nested evidenceA & B')

    def test_text_and_attributes_must_match_the_same_element(self):
        dom = '<!-- <span id="count">3</span> --><span id="other">3</span><span id="count">2</span>'
        self.assertFalse(query(dom).has('span', {'id': 'count'}, text='3'))
        self.assertTrue(query(dom).has('span', {'id': 'count'}, text='2'))
        self.assertFalse(query(dom).has('span', {'id': 'missing'}, text=''))

    def test_text_matches_decoded_content_despite_markup_and_attribute_order(self):
        dom = '<span title="total" class="extra count" id="count">A &amp; <strong>B</strong></span><span id="empty"></span>'
        self.assertTrue(query(dom).has('span', {'id': 'count', 'class': 'count'}, text='A & B'))
        self.assertTrue(query(dom).has('span', {'id': 'empty'}, text=''))


if __name__ == "__main__":
    unittest.main()
