#!/usr/bin/env python3
import ast
from sage.all import sage_eval


RESTRICTED = {
    ast.Import,
    ast.ImportFrom,
    ast.With,
    ast.alias,
    ast.Attribute,
    ast.Assign,
    ast.AnnAssign,
    ast.AugAssign,
    ast.For,
    ast.Try,
    ast.ExceptHandler,
    ast.With,
    ast.withitem,
    ast.FunctionDef,
    ast.Lambda,
    ast.ClassDef,
    ast.If,
    ast.And,
    ast.comprehension,
    ast.In,
    ast.Await,
    ast.Global,
    ast.Gt,
    ast.ListComp,
    ast.Slice,
    ast.Return,
    ast.List,
    ast.Dict,
    ast.Lt,
    ast.AsyncFunctionDef,
    ast.Eq,
    ast.keyword,
    ast.Mult,
    ast.arguments,
    ast.FormattedValue,
    ast.Not,
    ast.BoolOp,
    ast.Or,
    ast.Compare,
    ast.GtE,
    ast.ImportFrom,
    ast.Tuple,
    ast.NotEq,
    ast.IfExp,
    ast.alias,
    ast.UnaryOp,
    ast.arg,
    ast.JoinedStr,
}

RESTRICTED_TERMS = [
    'exec',
    'print',
    'import',
    'system', 
    'flag', 
    'spawn',
    'fork', 
    'open', 
    'subprocess', 
    'sys',
    'ast', 
    'os',
    'audit',
    'hook',
    'compile',
    '__new__',
    'frame',
    'eval',
    'interpreter',
    'ctypes',
    'open',
    'gc',
    'getattr',
    'setattr',
    'delattr',
    '__import__',
    '__builtins__',
    '__subclasses__',
    '__globals__',
    '__closure__',
    '__code__',
    '__dict__',
    'breakpoint',
    'help', 
    'exit',
    'dir',    
]

def check_ast(code):
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if type(node) in RESTRICTED:
                print(f"You Cant Use: {str(type(node))}")
                return False
        return True
    except SyntaxError:
        print("Invalid syntax!")
        return False

def check_RESTRICTED_terms(code):
    code_lower = code.lower()
    if not (code.isascii()):
        print('Hmmmmmm only ascii pls')
        return False
    for term in RESTRICTED_TERMS:
        if term in code_lower:
            print(f"RESTRICTED term: {term}")
            return False
    return True

def check_duplicates(code):
    allowed_duplicates = {'"','(',')'}
    seen = set()
    for char in code:
        if char in seen and char not in allowed_duplicates:
            print(f"Duplicate character found: {char}")
            return False
        seen.add(char)
    return True

def banner():
    print("Enter your expression here: ")
    code = input("")
    return code.strip()

def main():
    code = banner()
    
    if not check_ast(code) or not check_RESTRICTED_terms(code) or not check_duplicates(code):
        print("Security check failed!")
        return
    
    try:
        result = sage_eval(code)
        print(f"Result: {result}")

    except Exception as e:
        print(f"Evaluation error: {str(e)}")
        exit(0)

if __name__ == "__main__":
    main()