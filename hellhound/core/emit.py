class Emit:
    """
    Unified emit handler.
    Works as:
      emit("message")
      emit.info("message")
      emit.warn("message")
      emit.success("message")
    """

    def __init__(self, sink):
        self.sink = sink  # function that actually prints / streams

    def __call__(self, msg):
        self.sink(msg)

    def info(self, msg):
        self.sink(f"[*] {msg}")

    def warn(self, msg):
        self.sink(f"[!] {msg}")

    def success(self, msg):
        self.sink(f"[✓] {msg}")
