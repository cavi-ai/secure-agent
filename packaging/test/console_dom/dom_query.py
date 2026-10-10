"""Structural queries over Chrome's rendered DOM, using only the stdlib."""

from functools import lru_cache
from html.parser import HTMLParser

VOID = frozenset("area base br col embed hr img input link meta param source track wbr".split())


def starts_with(value):
    return lambda actual: actual is not None and actual.startswith(value)


class Node:
    def __init__(self, source, tag="", attrs=None, start=0, content_start=0):
        self.source, self.tag, self.attrs = source, tag, dict(attrs or [])
        self.start, self.content_start = start, content_start
        self.content_end = self.end = len(source)
        self.children, self.parts = [], []

    @property
    def html(self):
        return self.source[self.start:self.end]

    @property
    def inner_html(self):
        return self.source[self.content_start:self.content_end]

    @property
    def text(self):
        if self.tag in ("script", "style"):
            return ""
        return "".join(part.text if isinstance(part, Node) else part for part in self.parts)

    def find_all(self, tag=None, attrs=None):
        result = []
        for child in self.children:
            if (tag is None or child.tag == tag) and all(
                key in child.attrs and (value is None or
                (value(child.attrs[key]) if callable(value) else
                 set(value.split()).issubset((child.attrs[key] or "").split()) if key == "class" else child.attrs[key] == value))
                for key, value in (attrs or {}).items()
            ):
                result.append(child)
            result.extend(child.find_all(tag, attrs))
        return result

    def find(self, tag=None, attrs=None):
        return next(iter(self.find_all(tag, attrs)), None)

    def has(self, tag=None, attrs=None):
        return self.find(tag, attrs) is not None


class _Parser(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.source = source
        self.lines = [0]
        self.lines.extend(i + 1 for i, c in enumerate(source) if c == "\n")
        self.root = Node(source)
        self.stack = [self.root]

    def source_position(self):
        line, column = self.getpos()
        return self.lines[line - 1] + column

    def handle_starttag(self, tag, attrs):
        start = self.source_position()
        node = Node(self.source, tag, attrs, start, start + len(self.get_starttag_text()))
        self.stack[-1].children.append(node)
        self.stack[-1].parts.append(node)
        if tag in VOID:
            node.content_end = node.end = node.content_start
        else:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID:
            node = self.stack.pop()
            node.content_end = node.end = node.content_start

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                start = self.source_position()
                end = self.source.find(">", start) + 1
                for node in self.stack[i:]:
                    node.content_end = start
                    node.end = end
                del self.stack[i:]
                break

    def handle_data(self, data):
        self.stack[-1].parts.append(data)


@lru_cache(maxsize=8)
def query(source):
    parser = _Parser(source)
    parser.feed(source)
    parser.close()
    return parser.root
