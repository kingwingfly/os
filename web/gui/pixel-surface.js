// Runs on the owning process Worker. A latched GPU canvas is disposable.
export class PixelSurface {
  constructor(report) { this.report = report; this.current = new Map(); this.desiredSizes = new Map(); }
  dispose({ surface_id, generation }) {
    const record = this.current.get(surface_id);
    if (record && record.generation !== generation) return;
    this.desiredSizes.delete(surface_id);
    this.current.delete(surface_id);
    record?.device?.destroy?.();
  }
  async bind({ surface_id, generation, canvas, backend, decoration }) {
    const old = this.current.get(surface_id);
    if (old && old.generation >= generation) return;
    const record = { canvas, generation, decoration };
    this.current.set(surface_id, record);
    old?.device?.destroy?.();
    const size = this.desiredSizes.get(surface_id);
    if (size) this.resize(surface_id, size.width, size.height);
    const lost = reason => {
      if (this.current.get(surface_id) !== record || record.lost) return;
      record.lost = true;
      this.report({ op: 'surface_device_lost', surface_id, generation, reason: String(reason).slice(0, 256), fallback: 'software2d' });
    };
    for (const type of ['contextlost', 'webglcontextlost']) {
      canvas.addEventListener?.(type, e => { e.preventDefault(); lost('context lost'); });
    }
    if (backend !== 'software2d' && globalThis.navigator?.gpu) {
      try {
        const gpu = navigator.gpu;
        const adapter = await gpu.requestAdapter();
        if (this.current.get(surface_id) !== record) return;
        if (adapter) {
          record.device = await adapter.requestDevice();
          if (this.current.get(surface_id) !== record) { record.device.destroy(); return; }
          record.context = canvas.getContext('webgpu');
          if (!record.context) throw new Error('WebGPU context unavailable');
          record.context.configure({ device: record.device, format: gpu.getPreferredCanvasFormat(), alphaMode: 'opaque' });
          record.device.lost.then(info => lost(info.message || info.reason));
        }
      } catch (e) { lost(e.message); return; }
    }
    try { record.context ??= canvas.getContext('2d'); }
    catch (e) { lost(e.message); return; }
    if (!record.context) { lost('2D context unavailable'); return; }
    this.report({ op: 'surface_ready', surface_id, generation, backend: record.device ? 'web_gpu' : 'software2d', width: canvas.width, height: canvas.height });
  }
  resize(id, width, height) {
    this.desiredSizes.set(id, { width, height });
    const r = this.current.get(id);
    if (!r || r.lost) return;
    // Configure describes the window rectangle. The canvas uses its content box.
    width = Math.max(1, width - (r.decoration?.width ?? 0));
    height = Math.max(1, height - (r.decoration?.height ?? 0));
    if (r.canvas.width === width && r.canvas.height === height) return;
    r.canvas.width = width; r.canvas.height = height;
    if (r.color != null) this.paint(id, r.generation, r.color);
  }
  paint(id, generation, color) {
    const r = this.current.get(id);
    if (!r || r.generation !== generation || r.lost || !r.context) return;
    r.color = color;
    const rgb = [color >> 16 & 255, color >> 8 & 255, color & 255];
    if (r.device) {
      const encoder = r.device.createCommandEncoder();
      const pass = encoder.beginRenderPass({ colorAttachments: [{ view: r.context.getCurrentTexture().createView(), loadOp: 'clear', storeOp: 'store', clearValue: [...rgb.map(n => n / 255), 1] }] });
      pass.end(); r.device.queue.submit([encoder.finish()]);
    } else {
      const ctx = r.context, { width, height } = r.canvas;
      ctx.fillStyle = 'rgb(' + rgb.join(',') + ')'; ctx.fillRect(0, 0, width, height);
      ctx.fillStyle = '#e3bd72'; ctx.beginPath(); ctx.arc(width * .47, height * .46, Math.min(width, height) * .27, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = '#284940'; ctx.fillRect(width * .24, height * .62, width * .52, height * .1);
    }
  }
}
