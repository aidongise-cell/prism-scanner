"""
Lightweight intra-file taint analysis for Python.

Tracks data flow from Sources (external input) to Sinks (dangerous functions).
MVP scope: same-file, single-level function parameter passing.
"""
import ast
from enum import Enum
from dataclasses import dataclass, field


class TaintLevel(Enum):
    LITERAL = "literal"      # constant value — safe
    INTERNAL = "internal"    # internal variable, origin unclear
    EXTERNAL = "external"    # user input, env var, network response — dangerous
    UNKNOWN = "unknown"      # cannot determine


# Functions whose return values are tainted as EXTERNAL
SOURCE_FUNCTIONS = {
    # Environment variables
    ("os", "getenv"): "env_var",
    ("os", "environ", "get"): "env_var",
    # User input
    ("builtins", "input"): "user_input",
    ("", "input"): "user_input",
    # Network responses
    ("requests", "get"): "network",
    ("requests", "post"): "network",
    ("requests", "put"): "network",
    ("requests", "delete"): "network",
    ("requests", "patch"): "network",
    ("httpx", "get"): "network",
    ("httpx", "post"): "network",
    ("urllib", "request", "urlopen"): "network",
    # Command line
    ("sys", "argv"): "cli_args",
    # File reads (could be tainted depending on path)
    ("builtins", "open"): "file_read",
}

# Attribute access patterns that produce EXTERNAL taint
SOURCE_ATTRIBUTES = {
    "os.environ": "env_var",
    "sys.argv": "cli_args",
    "request.args": "user_input",
    "request.form": "user_input",
    "request.json": "user_input",
    "request.data": "user_input",
}


@dataclass
class TaintInfo:
    level: TaintLevel
    source_type: str = ""      # e.g. "env_var", "network", "user_input"
    source_desc: str = ""      # human-readable description
    source_line: int = 0


@dataclass
class TaintContext:
    """Tracks taint state for variables within a single file."""
    variables: dict[str, TaintInfo] = field(default_factory=dict)

    def set_taint(self, name: str, info: TaintInfo):
        self.variables[name] = info

    def get_taint(self, name: str) -> TaintInfo:
        return self.variables.get(name, TaintInfo(level=TaintLevel.UNKNOWN))

    def resolve_node(self, node: ast.expr) -> TaintInfo:
        """Determine taint level of an AST expression node."""
        # String/number/bytes constants
        if isinstance(node, ast.Constant):
            return TaintInfo(level=TaintLevel.LITERAL)

        # f-string — tainted if any value is tainted
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    inner = self.resolve_node(value.value)
                    if inner.level == TaintLevel.EXTERNAL:
                        return inner
            return TaintInfo(level=TaintLevel.LITERAL)

        # Variable name lookup
        if isinstance(node, ast.Name):
            return self.get_taint(node.id)

        # String concatenation: "a" + var
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.resolve_node(node.left)
            right = self.resolve_node(node.right)
            # If either side is EXTERNAL, result is EXTERNAL
            if left.level == TaintLevel.EXTERNAL:
                return left
            if right.level == TaintLevel.EXTERNAL:
                return right
            if left.level == TaintLevel.LITERAL and right.level == TaintLevel.LITERAL:
                return TaintInfo(level=TaintLevel.LITERAL)
            return TaintInfo(level=TaintLevel.INTERNAL)

        # Subscript: dict["key"], list[0], os.environ["KEY"]
        if isinstance(node, ast.Subscript):
            val_taint = self.resolve_node(node.value)
            return val_taint

        # Attribute access: obj.attr
        if isinstance(node, ast.Attribute):
            full_name = _get_attribute_string(node)
            if full_name in SOURCE_ATTRIBUTES:
                return TaintInfo(
                    level=TaintLevel.EXTERNAL,
                    source_type=SOURCE_ATTRIBUTES[full_name],
                    source_desc=full_name,
                    source_line=node.lineno,
                )
            # Propagate taint from the value
            return self.resolve_node(node.value)

        # Function/method call
        if isinstance(node, ast.Call):
            return self._resolve_call_taint(node)

        # List/tuple/set/dict literals — check elements
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                inner = self.resolve_node(elt)
                if inner.level == TaintLevel.EXTERNAL:
                    return inner
            return TaintInfo(level=TaintLevel.LITERAL)

        if isinstance(node, ast.Dict):
            for v in node.values:
                if v is not None:
                    inner = self.resolve_node(v)
                    if inner.level == TaintLevel.EXTERNAL:
                        return inner
            return TaintInfo(level=TaintLevel.LITERAL)

        return TaintInfo(level=TaintLevel.UNKNOWN)

    def _resolve_call_taint(self, node: ast.Call) -> TaintInfo:
        """Check if a function call returns a tainted value."""
        func_name = _get_call_name(node)

        # Check against known source functions
        for source_key, source_type in SOURCE_FUNCTIONS.items():
            source_name = ".".join(source_key)
            if func_name == source_name or func_name.endswith("." + source_key[-1]):
                return TaintInfo(
                    level=TaintLevel.EXTERNAL,
                    source_type=source_type,
                    source_desc=f"{func_name}()",
                    source_line=node.lineno,
                )

        # .read(), .text, .json() on tainted objects propagate taint
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("read", "json", "text", "decode", "content"):
                obj_taint = self.resolve_node(node.func.value)
                if obj_taint.level == TaintLevel.EXTERNAL:
                    return obj_taint

        # .format() on strings — check if any argument is tainted
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            for arg in node.args:
                arg_taint = self.resolve_node(arg)
                if arg_taint.level == TaintLevel.EXTERNAL:
                    return arg_taint
            for kw in node.keywords:
                if kw.value:
                    kw_taint = self.resolve_node(kw.value)
                    if kw_taint.level == TaintLevel.EXTERNAL:
                        return kw_taint

        return TaintInfo(level=TaintLevel.UNKNOWN)


def _get_call_name(node: ast.Call) -> str:
    """Extract the full dotted name of a function call."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return _get_attribute_string(node.func)
    return ""


def _get_attribute_string(node: ast.Attribute) -> str:
    """Convert an Attribute AST node to a dotted string like 'os.path.join'."""
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))
