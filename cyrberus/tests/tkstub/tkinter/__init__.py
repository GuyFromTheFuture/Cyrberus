"""Minimal tkinter stand-in: records draw calls instead of painting."""
class _Font:
    @staticmethod
    def families(root=None):
        return ("DejaVu Sans", "Liberation Sans", "Helvetica")
font = type("m", (), {"families": _Font.families, "Font": object})()

class Canvas:
    def __init__(self, master=None, **kw):
        self.calls = []
        self._w, self._h = 800, 480
    def pack(self, **kw): pass
    def bind(self, *a, **kw): pass
    def configure(self, **kw): self.calls.append(("configure", kw))
    def winfo_width(self): return self._w
    def winfo_height(self): return self._h
    def delete(self, *a): self.calls.append(("delete", a))
    def create_rectangle(self, *a, **kw): self.calls.append(("rect", a, kw)); return 1
    def create_text(self, *a, **kw): self.calls.append(("text", a, kw)); return 1
    def create_line(self, *a, **kw): self.calls.append(("line", a, kw)); return 1
    def create_oval(self, *a, **kw): self.calls.append(("oval", a, kw)); return 1
    def create_polygon(self, *a, **kw): self.calls.append(("poly", a, kw)); return 1
    def create_arc(self, *a, **kw): self.calls.append(("arc", a, kw)); return 1

class Tk:
    def __init__(self): self.after_calls = []
    def title(self, *a): pass
    def configure(self, **kw): pass
    def geometry(self, *a): pass
    def attributes(self, *a): pass
    def bind(self, *a): pass
    def destroy(self): pass
    def after(self, ms, fn): self.after_calls.append((ms, fn))
    def mainloop(self): pass
