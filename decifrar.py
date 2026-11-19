from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from rsa_core import decifrar


class ModuloB(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Módulo B - Decifrar")
        self.geometry("780x640")
        self.minsize(660, 540)

        self.n = tk.StringVar(master=self)
        self.d = tk.StringVar(master=self)

        conteudo = ttk.Frame(self, padding=14)
        conteudo.pack(fill="both", expand=True)
        conteudo.columnconfigure(0, weight=1)
        conteudo.rowconfigure(1, weight=1)
        conteudo.rowconfigure(3, weight=1)

        chave = ttk.LabelFrame(conteudo, text="Chave privada (n, d)", padding=10)
        chave.grid(row=0, column=0, sticky="ew")
        chave.columnconfigure(1, weight=1)
        ttk.Label(chave, text="n:").grid(row=0, column=0, padx=(0, 8))
        ttk.Entry(chave, textvariable=self.n).grid(
            row=0, column=1, sticky="ew", pady=3
        )
        ttk.Label(chave, text="d:").grid(row=1, column=0, padx=(0, 8))
        ttk.Entry(chave, textvariable=self.d).grid(
            row=1, column=1, sticky="ew", pady=3
        )

        entrada = ttk.LabelFrame(conteudo, text="Texto cifrado", padding=8)
        entrada.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        ttk.Button(
            entrada, text="Abrir .rsa", command=self.abrir_cifra
        ).pack(anchor="w", pady=(0, 8))
        self.cifra = ScrolledText(entrada, height=8, wrap="word")
        self.cifra.pack(fill="both", expand=True)

        ttk.Button(
            conteudo, text="Decifrar", command=self.decifrar_texto
        ).grid(row=2, column=0, sticky="w", pady=10)

        saida = ttk.LabelFrame(conteudo, text="Texto claro (UTF-8)", padding=8)
        saida.grid(row=3, column=0, sticky="nsew")
        self.texto = ScrolledText(
            saida, height=8, wrap="word", state="disabled"
        )
        self.texto.pack(fill="both", expand=True)

    def exibir_texto(self, texto):
        self.texto.configure(state="normal")
        self.texto.delete("1.0", "end")
        self.texto.insert("1.0", texto)
        self.texto.configure(state="disabled")

    def abrir_cifra(self):
        caminho = filedialog.askopenfilename(
            title="Abrir texto cifrado",
            filetypes=[("Cifra RSA", "*.rsa")],
        )
        if not caminho:
            return

        try:
            conteudo = Path(caminho).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as erro:
            messagebox.showerror("Erro ao abrir", str(erro))
            return

        self.cifra.delete("1.0", "end")
        self.cifra.insert("1.0", conteudo)
        self.exibir_texto("")

    def decifrar_texto(self):
        self.exibir_texto("")
        try:
            n = int(self.n.get())
            d = int(self.d.get())
        except ValueError:
            messagebox.showerror("Chave inválida", "Informe n e d inteiros.")
            return

        try:
            resultado = decifrar(self.cifra.get("1.0", "end-1c"), n, d)
        except ValueError as erro:
            messagebox.showerror("Não foi possível decifrar", str(erro))
            return
        self.exibir_texto(resultado)


if __name__ == "__main__":
    ModuloB().mainloop()
