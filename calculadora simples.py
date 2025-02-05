import tkinter as tk
from tkinter import messagebox
import tkinter.font as tkFont

class SimpleCalculator:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Calculator")
        self.root.geometry("400x500")
        self.root.resizable(True, True)
        
        self.expression = ""
        self.input_text = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        input_frame = tk.Frame(self.root, width=400, height=50, bd=0, highlightbackground="black", highlightcolor="black", highlightthickness=2)
        input_frame.pack(side=tk.TOP, fill=tk.BOTH)

        input_field = tk.Entry(input_frame, font=('arial', 24, 'bold'), textvariable=self.input_text, bg="#eee", bd=0, justify=tk.RIGHT)
        input_field.grid(row=0, column=0)
        input_field.pack(ipady=10, fill=tk.BOTH, expand=True)

        btns_frame = tk.Frame(self.root, bg="grey")
        btns_frame.pack(fill=tk.BOTH, expand=True)

        buttons = [
            '7', '8', '9', 'C',
            '4', '5', '6', '/',
            '1', '2', '3', '*',
            '0', '.', '=', '+',
            '-', '(', ')', 'CE'
        ]

        row = 0
        col = 0

        for button in buttons:
            if button == '=':
                btn = tk.Button(btns_frame, text=button, fg="black", bg="#eee", cursor="hand2", font=('arial', 18, 'bold'), command=lambda: self.evaluate())
            elif button == 'C':
                btn = tk.Button(btns_frame, text=button, fg="black", bg="#eee", cursor="hand2", font=('arial', 18, 'bold'), command=lambda: self.clear())
            elif button == 'CE':
                btn = tk.Button(btns_frame, text=button, fg="black", bg="#eee", cursor="hand2", font=('arial', 18, 'bold'), command=lambda: self.clear_entry())
            else:
                btn = tk.Button(btns_frame, text=button, fg="black", bg="#fff", cursor="hand2", font=('arial', 18, 'bold'), command=lambda button=button: self.click(button))
            
            btn.grid(row=row, column=col, padx=1, pady=1, sticky="nsew")
            col += 1
            if col > 3:
                col = 0
                row += 1

        for i in range(5):
            btns_frame.grid_rowconfigure(i, weight=1)
            btns_frame.grid_columnconfigure(i, weight=1)

    def click(self, item):
        self.expression += str(item)
        self.input_text.set(self.expression)

    def clear(self):
        self.expression = ""
        self.input_text.set("")

    def clear_entry(self):
        self.expression = self.expression[:-1]
        self.input_text.set(self.expression)

    def evaluate(self):
        try:
            result = str(eval(self.expression))
            self.input_text.set(result)
            self.expression = result
        except Exception as e:
            messagebox.showerror("Error", "Invalid Input")
            self.expression = ""
            self.input_text.set("")

if __name__ == "__main__":
    root = tk.Tk()
    calculator = SimpleCalculator(root)
    root.mainloop()
