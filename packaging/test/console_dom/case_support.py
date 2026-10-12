import html

import json

import re

from html.parser import HTMLParser

from dom_query import query as dom_query, starts_with

import payload_cases

def pre(dom_text, pid):
    node = dom_query(dom_text).find('pre', {'id': pid})
    return node.inner_html if node else ''

def log_row_nodes(dom):
    root = dom_query(dom) if isinstance(dom, str) else dom
    return {node.attrs['data-row-key']: node for node in root.find_all('li', {'class': 'log-row', 'data-row-key': None})}

def log_rows(dom_text):
    return {key: node.html for key, node in log_row_nodes(dom_text).items()}

class PolicyRowCounter(HTMLParser):

    def __init__(self):
        super().__init__()
        self.scopes = []
        self.counts = {}

    def handle_starttag(self, tag, attrs):
        if tag != 'div':
            return
        attributes = dict(attrs)
        scope = attributes.get('data-policy') or (self.scopes[-1] if self.scopes else None)
        self.scopes.append(scope)
        if scope and 'policy-row' in attributes.get('class', '').split():
            self.counts[scope] = self.counts.get(scope, 0) + 1

    def handle_endtag(self, tag):
        if tag == 'div' and self.scopes:
            self.scopes.pop()
