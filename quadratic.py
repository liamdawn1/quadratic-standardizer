from __future__ import annotations

import re
import sys
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import sympy as sp
from sympy.parsing.sympy_parser import (
    parse_expr,
    standard_transformations,
    implicit_multiplication_application,
)


try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass


TRANSFORMS = standard_transformations + (implicit_multiplication_application,)
x = sp.Symbol("x")


_ALLOWED = re.compile(r"^[0-9xX+\-*/^=().\s]+$")


_SUPERS = str.maketrans(
    {
        "0": "⁰",
        "1": "¹",
        "2": "²",
        "3": "³",
        "4": "⁴",
        "5": "⁵",
        "6": "⁶",
        "7": "⁷",
        "8": "⁸",
        "9": "⁹",
        "-": "⁻",
    }
)


class QuadraticParseError(Exception):
    pass


def sanitize(user_in: str) -> str:
    s = user_in.strip()
    if not s:
        raise QuadraticParseError("Empty input.")
    if not _ALLOWED.match(s):
        raise QuadraticParseError(
            "Invalid characters (only digits, x, + - * / ^ = ( ) . and spaces are allowed)."
        )

    s = s.lower()
    s = s.replace("^", "**")
    s = re.sub(r"\s+", " ", s)

    if s.count("=") > 1:
        raise QuadraticParseError("Too many '=' signs (use at most one).")

    bal = 0
    for ch in s:
        if ch == "(":
            bal += 1
        elif ch == ")":
            bal -= 1
            if bal < 0:
                raise QuadraticParseError("Unbalanced parentheses.")
    if bal != 0:
        raise QuadraticParseError("Unbalanced parentheses.")

    return s


def parse_sympy_expr(s: str) -> sp.Expr:
    safe_globals = {"Integer": sp.Integer, "Rational": sp.Rational, "Float": sp.Float}
    try:
        return parse_expr(
            s,
            local_dict={"x": x},
            global_dict=safe_globals,
            transformations=TRANSFORMS,
            evaluate=True,
        )
    except Exception as e:
        raise QuadraticParseError(f"Could not parse expression: {e}")


def to_zero_expression(s: str) -> sp.Expr:
    
    if "=" in s:
        lhs, rhs = s.split("=", 1)
        lhs, rhs = lhs.strip(), rhs.strip()
        if not lhs or not rhs:
            raise QuadraticParseError("Invalid equation: missing LHS or RHS.")
        return parse_sympy_expr(f"({lhs})-({rhs})")
    return parse_sympy_expr(s)


def classify_and_standardize(expr0: sp.Expr) -> tuple[str, sp.Expr]:
    """
    Returns (kind, expr) where expr is expanded/simplified.
    kind: quadratic | linear | constant | identity | higher
    """
    expr = sp.expand(expr0)
    expr = sp.simplify(expr)

    try:
        poly = sp.Poly(expr, x)
    except Exception:
        raise QuadraticParseError("After simplification, input is not a polynomial in x.")

    deg = poly.degree()

    if deg == 2:
        return "quadratic", expr
    if deg == 1:
        return "linear", expr
    if deg == 0:
        if sp.simplify(expr) == 0:
            return "identity", expr
        return "constant", expr
    if deg < 0:
        return "identity", expr

    return "higher", expr


def quadratic_standard_form(expr: sp.Expr) -> sp.Expr:
    """Force exact ax^2 + bx + c from an already-quadratic expression."""
    poly = sp.Poly(sp.expand(expr), x)
    a = sp.simplify(poly.nth(2))
    b = sp.simplify(poly.nth(1))
    c = sp.simplify(poly.nth(0))
    return sp.expand(a * x**2 + b * x + c)



def to_superscripts(s: str) -> str:
    """
    Convert **integer powers into unicode superscripts:
      x**2 -> x²
      (x+1)**10 -> (x+1)¹⁰
    """
    def repl(m: re.Match) -> str:
        base = m.group(1)
        exp = m.group(2)
        return base + exp.translate(_SUPERS)

    
    return re.sub(r"(\([^()]+\)|[A-Za-z0-9_]+)\*\*([\-]?\d+)", repl, s)


def clean_sympy_string(expr: sp.Expr) -> str:
    """
    Make a stable, single-line string for Treeview:
    - Use sympy sstr (single-line)
    - Remove some noisy '*' in simple cases
    - Convert **powers to superscripts
    """
    s = sp.sstr(expr)

   
    s = s.replace("*x", "x")
    s = s.replace(")/", ")/")  

    
    s = to_superscripts(s)

    return s


def format_equation(expr: sp.Expr) -> str:
    return f"{clean_sympy_string(expr)} = 0"



@dataclass
class RowResult:
    line_no: int
    raw: str
    kind: str
    output: str


def process_file(path: str) -> list[RowResult]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(str(p))

    rows: list[RowResult] = []
    for i, raw in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        try:
            s2 = sanitize(line)
            expr0 = to_zero_expression(s2)
            kind, std_expr = classify_and_standardize(expr0)

            if kind == "quadratic":
                q = quadratic_standard_form(std_expr)
                out = format_equation(q)
                rows.append(RowResult(i, line, "Quadratic", out))
            elif kind == "linear":
                rows.append(RowResult(i, line, "Linear", "Linear (degree 1) — not quadratic"))
            elif kind == "constant":
                rows.append(RowResult(i, line, "Constant", "Constant (degree 0) — no x term"))
            elif kind == "identity":
                rows.append(RowResult(i, line, "Identity", "Identity (0 = 0) — always true"))
            else:
                deg = sp.Poly(std_expr, x).degree()
                rows.append(RowResult(i, line, "Higher", f"Higher degree polynomial (degree {deg}) — not quadratic"))

        except QuadraticParseError as e:
            rows.append(RowResult(i, line, "Invalid", f"Invalid input: {e}"))
        except Exception as e:
            rows.append(RowResult(i, line, "Error", f"Unexpected error: {e}"))

    return rows



class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Quadratic Standardizer (File → ax² + bx + c = 0)")
        self.geometry("1200x720")
        self.minsize(900, 550)

        self._build_ui()

    def _build_ui(self):
       
        style = ttk.Style()
        try:
            style.configure("Treeview", font=("Segoe UI", 10))
            style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        except Exception:
            pass

        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        self.file_var = tk.StringVar(value="")
        ttk.Label(top, text="File:").pack(side="left")
        ttk.Entry(top, textvariable=self.file_var).pack(side="left", fill="x", expand=True, padx=(6, 6))
        ttk.Button(top, text="Browse…", command=self.browse).pack(side="left")
        ttk.Button(top, text="Run", command=self.run).pack(side="left", padx=(6, 0))

        mid = ttk.Frame(self, padding=(10, 0, 10, 10))
        mid.pack(fill="both", expand=True)

        columns = ("line", "input", "type", "result")
        self.tree = ttk.Treeview(mid, columns=columns, show="headings", height=18)

        self.tree.heading("line", text="Line")
        self.tree.heading("input", text="Input")
        self.tree.heading("type", text="Type")
        self.tree.heading("result", text="Standard / Message")

        self.tree.column("line", width=70, anchor="center")
        self.tree.column("input", width=420, anchor="w")
        self.tree.column("type", width=110, anchor="center")
        self.tree.column("result", width=560, anchor="w")

        vsb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(mid, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        mid.rowconfigure(0, weight=1)
        mid.columnconfigure(0, weight=1)

        bottom = ttk.Frame(self, padding=(10, 0, 10, 10))
        bottom.pack(fill="both")

        ttk.Label(bottom, text="Selected row details:").pack(anchor="w")
        self.details = tk.Text(bottom, height=8, wrap="word")
        self.details.pack(fill="both")

        btns = ttk.Frame(self, padding=(10, 0, 10, 10))
        btns.pack(fill="x")

        ttk.Button(btns, text="Copy Selected", command=self.copy_selected).pack(side="left")
        ttk.Button(btns, text="Copy All", command=self.copy_all).pack(side="left", padx=(6, 0))
        ttk.Button(btns, text="Clear", command=self.clear).pack(side="left", padx=(6, 0))

        self.tree.bind("<<TreeviewSelect>>", self.on_select)

    def browse(self):
        path = filedialog.askopenfilename(
            title="Select equations .txt file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            self.file_var.set(path)

    def run(self):
        path = self.file_var.get().strip()
        if not path:
            messagebox.showwarning("No file", "Pick a file first.")
            return
        try:
            rows = process_file(path)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        self.clear()
        for r in rows:
            self.tree.insert("", "end", values=(r.line_no, r.raw, r.kind, r.output))

        if not rows:
            messagebox.showinfo("No data", "No equations found (file might be empty or only comments).")

    def clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.details.delete("1.0", "end")

    def on_select(self, _evt=None):
        sel = self.tree.selection()
        if not sel:
            return
        item = sel[0]
        line_no, raw, kind, out = self.tree.item(item, "values")
        text = (
            f"Line: {line_no}\n"
            f"Type: {kind}\n\n"
            f"Input:\n{raw}\n\n"
            f"Output / Message:\n{out}\n"
        )
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)

    def copy_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Copy", "Select one or more rows first.")
            return
        lines = []
        for item in sel:
            line_no, raw, kind, out = self.tree.item(item, "values")
            lines.append(f"LINE {line_no} [{kind}]: {raw}  =>  {out}")
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))

    def copy_all(self):
        items = self.tree.get_children()
        if not items:
            messagebox.showinfo("Copy", "Nothing to copy yet.")
            return
        lines = []
        for item in items:
            line_no, raw, kind, out = self.tree.item(item, "values")
            lines.append(f"LINE {line_no} [{kind}]: {raw}  =>  {out}")
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))


if __name__ == "__main__":
    App().mainloop()