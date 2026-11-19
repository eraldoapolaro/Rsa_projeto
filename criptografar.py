from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from rsa_core import criptografar, gerar_chaves, gerar_chaves_aleatorias


class ModuloA(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Módulo A - Criptografar")
        self.geometry("780x760")
        self.minsize(660, 680)

        self.p = tk.StringVar(master=self)
        self.q = tk.StringVar(master=self)
        self.n = tk.StringVar(master=self)
        self.e = tk.StringVar(master=self)

        conteudo = ttk.Frame(self, padding=14)
        conteudo.pack(fill="both", expand=True)
        conteudo.columnconfigure(0, weight=1)
        conteudo.rowconfigure(3, weight=1)
        conteudo.rowconfigure(5, weight=1)

        primos = ttk.LabelFrame(conteudo, text="Geração de chaves", padding=10)
        primos.grid(row=0, column=0, sticky="ew")
        primos.columnconfigure(1, weight=1)

        ttk.Label(primos, text="p:").grid(row=0, column=0, padx=(0, 8))
        ttk.Entry(primos, textvariable=self.p).grid(
            row=0, column=1, sticky="ew", pady=3
        )
        ttk.Label(primos, text="q:").grid(row=1, column=0, padx=(0, 8))
        ttk.Entry(primos, textvariable=self.q).grid(
            row=1, column=1, sticky="ew", pady=3
        )

        botoes = ttk.Frame(primos)
        botoes.grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Button(
            botoes, text="Gerar chaves com p e q", command=self.gerar_manual
        ).pack(side="left", padx=(0, 8))
        ttk.Button(
            botoes, text="Gerar p e q aleatórios", command=self.gerar_aleatorio
        ).pack(side="left")

        publica = ttk.LabelFrame(
            conteudo, text="Chave pública (n, e)", padding=10
        )
        publica.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        publica.columnconfigure(1, weight=1)
        ttk.Label(publica, text="n:").grid(row=0, column=0, padx=(0, 8))
        ttk.Entry(publica, textvariable=self.n).grid(
            row=0, column=1, sticky="ew", pady=3
        )
        ttk.Label(publica, text="e:").grid(row=1, column=0, padx=(0, 8))
        ttk.Entry(publica, textvariable=self.e).grid(
            row=1, column=1, sticky="ew", pady=3
        )

        privada = ttk.LabelFrame(
            conteudo, text="Chave privada gerada (n, d)", padding=8
        )
        privada.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        self.privada = ScrolledText(
            privada, height=3, wrap="char", state="disabled"
        )
        self.privada.pack(fill="x")

        entrada = ttk.LabelFrame(conteudo, text="Texto claro (UTF-8)", padding=8)
        entrada.grid(row=3, column=0, sticky="nsew", pady=(10, 0))
        self.texto = ScrolledText(entrada, height=4, wrap="word")
        self.texto.pack(fill="both", expand=True)

        ttk.Button(
            conteudo, text="Criptografar", command=self.criptografar_texto
        ).grid(row=4, column=0, sticky="w", pady=10)

        saida = ttk.LabelFrame(conteudo, text="Texto cifrado", padding=8)
        saida.grid(row=5, column=0, sticky="nsew")
        self.cifra = ScrolledText(
            saida, height=5, wrap="word", state="disabled"
        )
        self.cifra.pack(fill="both", expand=True)

        self.salvar = ttk.Button(
            conteudo,
            text="Salvar .rsa",
            command=self.salvar_cifra,
            state="disabled",
        )
        self.salvar.grid(row=6, column=0, sticky="w", pady=(10, 0))

    def exibir(self, campo, texto):
        campo.configure(state="normal")
        campo.delete("1.0", "end")
        campo.insert("1.0", texto)
        campo.configure(state="disabled")

    def limpar_chaves(self):
        self.n.set("")
        self.e.set("")
        self.exibir(self.privada, "")
        self.exibir(self.cifra, "")
        self.salvar.configure(state="disabled")

    def exibir_chaves(self, publica, privada):
        n, e = publica
        self.n.set(str(n))
        self.e.set(str(e))
        self.exibir(self.privada, f"({privada[0]}, {privada[1]})")

    def gerar_manual(self):
        self.limpar_chaves()
        try:
            p = int(self.p.get())
            q = int(self.q.get())
        except ValueError:
            messagebox.showerror("Valores inválidos", "Informe p e q inteiros.")
            return

        try:
            publica, privada = gerar_chaves(p, q)
        except ValueError as erro:
            messagebox.showerror("Primos inválidos", str(erro))
            return
        self.exibir_chaves(publica, privada)

    def gerar_aleatorio(self):
        self.limpar_chaves()
        p, q, publica, privada = gerar_chaves_aleatorias()
        self.p.set(str(p))
        self.q.set(str(q))
        self.exibir_chaves(publica, privada)

    def criptografar_texto(self):
        self.exibir(self.cifra, "")
        self.salvar.configure(state="disabled")
        try:
            n = int(self.n.get())
            e = int(self.e.get())
        except ValueError:
            messagebox.showerror("Chave inválida", "Informe n e e inteiros.")
            return

        try:
            texto = self.texto.get("1.0", "end-1c")
            resultado = criptografar(texto, n, e)
        except ValueError as erro:
            messagebox.showerror("Não foi possível criptografar", str(erro))
            return
        self.exibir(self.cifra, resultado)
        self.salvar.configure(state="normal")

    def salvar_cifra(self):
        caminho = filedialog.asksaveasfilename(
            title="Salvar texto cifrado",
            defaultextension=".rsa",
            filetypes=[("Cifra RSA", "*.rsa")],
        )
        if not caminho:
            return
        if Path(caminho).suffix.lower() != ".rsa":
            messagebox.showerror("Nome inválido", "Use a extensão .rsa.")
            return

        try:
            Path(caminho).write_text(
                self.cifra.get("1.0", "end-1c"), encoding="utf-8"
            )
        except OSError as erro:
            messagebox.showerror("Erro ao salvar", str(erro))
            return
        messagebox.showinfo("Arquivo salvo", "A cifra foi salva em .rsa.")


if __name__ == "__main__":
    ModuloA().mainloop()
