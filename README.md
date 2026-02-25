# quadratic-standardizer

A Python-based equation standardization and classification tool.

This program reads algebraic expressions or equations and converts valid quadratic equations into standard form:

    ax^2 + bx + c = 0

---

## What This Program Does

- Accepts algebraic expressions or equations from a text file
- Moves all terms to one side of the equation
- Expands and simplifies expressions
- Classifies input as:
  - Quadratic
  - Linear
  - Constant
  - Identity
  - Higher-degree polynomial
  - Invalid expression
- Converts valid quadratics into standard form

---

## What This Program Does NOT Do

This program:

- Does NOT solve the quadratic equation
- Does NOT compute roots
- Does NOT apply the quadratic formula
- Does NOT factor the equation

It is strictly a standardization and classification engine.

---

## Technologies Used

- Python 3
- SymPy
- Tkinter

---

## Example

Input:
(x - 3)(x + 2)

Output:
x^2 - x - 6 = 0

---

## Author

Isaiah Johnson
