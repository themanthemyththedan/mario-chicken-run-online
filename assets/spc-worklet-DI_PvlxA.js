// AudioWorklet that plays .spc files with snes_spc.wasm (see tools/build_spc_wasm.py).
// Plain JavaScript on purpose: it is loaded by URL into the audio thread, outside the
// TypeScript build. src/engine/audio.ts is the only thing that talks to it.
//
// Messages in:   { type: "init", wasm: ArrayBuffer }
//                { type: "load", spc: ArrayBuffer, loop: boolean, seconds: number, fadeMs: number }
//                { type: "stop" }
//                { type: "pause" } | { type: "resume" }   hold the song where it is (a jingle
//                                    is playing over it), then carry on from the same spot
//                { type: "tempo", tempo: number }   music driver speed, 256 = normal (hurry-up)
// Messages out:  { type: "ready" } | { type: "loaded", ok: boolean } | { type: "ended" }
//                { type: "error", message: string }

const SPC_RATE = 32000;

class SpcProcessor extends AudioWorkletProcessor {
  constructor() {
    super();
    this.x = null;          // wasm exports
    this.playing = false;
    this.paused = false;    // a loaded song stays put: no rendering, silence out
    this.chunk = null;      // Int16Array view of the wasm output buffer
    this.chunkFrames = 0;   // frames rendered into it
    this.pos = 1;           // fractional position between prev and cur; >= 1 fetches a frame
    this.step = SPC_RATE / sampleRate;
    this.prevL = this.curL = 0;
    this.prevR = this.curR = 0;
    this.played = 0;        // output frames since load
    this.endAt = Infinity;  // output frame where the fade starts (loop: false)
    this.fadeFrames = 1;
    this.port.onmessage = (e) => this.onMessage(e.data);
  }

  onMessage(m) {
    try {
      if (m.type === "init") {
        const mod = new WebAssembly.Module(m.wasm);
        const imports = {};
        for (const i of WebAssembly.Module.imports(mod)) {
          (imports[i.module] ??= {})[i.name] = () => 0;
        }
        this.x = new WebAssembly.Instance(mod, imports).exports;
        if (this.x._initialize) this.x._initialize();
        this.port.postMessage({ type: "ready" });
      } else if (m.type === "load") {
        const x = this.x;
        const bytes = new Uint8Array(m.spc);
        new Uint8Array(x.memory.buffer, x.spc_file_buf(), bytes.length).set(bytes);
        const ok = x.spc_load(bytes.length) === 0;
        if (ok) x.spc_set_tempo(256);
        this.chunkFrames = 0;
        this.pos = 1;
        this.prevL = this.prevR = this.curL = this.curR = 0;
        this.played = 0;
        this.endAt = m.loop ? Infinity : Math.max(1, m.seconds) * sampleRate;
        this.fadeFrames = Math.max(1, (m.fadeMs / 1000) * sampleRate);
        this.playing = ok;
        this.port.postMessage({ type: "loaded", ok });
      } else if (m.type === "stop") {
        this.playing = false;
      } else if (m.type === "pause") {
        this.paused = true;
      } else if (m.type === "resume") {
        this.paused = false;
      } else if (m.type === "tempo") {
        if (this.x) this.x.spc_set_tempo(Math.round(m.tempo));
      }
    } catch (err) {
      this.playing = false;
      this.port.postMessage({ type: "error", message: String(err) });
    }
  }

  refill() {
    const x = this.x;
    const frames = Math.min(1024, x.spc_out_capacity());
    if (x.spc_render(frames) !== 0) {
      this.playing = false;
      this.port.postMessage({ type: "error", message: "spc_render failed" });
      return false;
    }
    // Re-create the view each time: it dies if wasm memory ever grows.
    this.chunk = new Int16Array(x.memory.buffer, x.spc_out_buf(), frames * 2);
    this.chunkFrames = frames;
    return true;
  }

  process(_inputs, outputs) {
    const out = outputs[0];
    if (!this.playing || this.paused || !out || out.length === 0) return true;
    const L = out[0];
    const R = out[1] ?? out[0];
    const mono = out.length < 2;
    for (let i = 0; i < L.length; i++) {
      // Linear interpolation between the previous and the current source frame; when
      // the context runs at 32000 Hz the step is 1 and this is a plain copy.
      while (this.pos >= 1) {
        if (this.chunkFrames === 0 && !this.refill()) return true;
        const c = this.chunk;
        const idx = c.length - this.chunkFrames * 2;
        this.prevL = this.curL;
        this.prevR = this.curR;
        this.curL = c[idx] / 32768;
        this.curR = c[idx + 1] / 32768;
        this.chunkFrames--;
        this.pos -= 1;
      }
      let gain = 1;
      if (this.played >= this.endAt) {
        gain = 1 - (this.played - this.endAt) / this.fadeFrames;
        if (gain <= 0) {
          this.playing = false;
          this.port.postMessage({ type: "ended" });
          return true;
        }
      }
      const l = (this.prevL + (this.curL - this.prevL) * this.pos) * gain;
      const r = (this.prevR + (this.curR - this.prevR) * this.pos) * gain;
      if (mono) L[i] = (l + r) / 2;
      else { L[i] = l; R[i] = r; }
      this.pos += this.step;
      this.played++;
    }
    return true;
  }
}

registerProcessor("spc-player", SpcProcessor);
