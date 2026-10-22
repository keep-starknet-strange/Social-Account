// Workers are terminated on cancellation because synchronous Wasm cannot service cancel messages.
// Every continuation checks run identity, including receipt persistence and worker transitions.
export class PublicRunController {
  constructor({
    workerFactory = (url) => new Worker(url, { type: "module" }),
    save,
    onStatus = () => {},
    onComplete = () => {},
    idFactory = () => crypto.randomUUID(),
  }) {
    Object.assign(this, {
      workerFactory,
      save,
      onStatus,
      onComplete,
      idFactory,
    });
    this.active = null;
  }
  cancel() {
    const run = this.active;
    this.active = null;
    if (run) {
      run.worker?.terminate();
      this.onStatus({ kind: "cancelled", id: run.id });
    }
  }
  start(request, source, { executionOnly = false, expectedWasm, build } = {}) {
    this.cancel();
    const run = { id: this.idFactory(), worker: null };
    this.active = run;
    const current = () => this.active === run;
    const fail = (e) => {
      if (!current()) return;
      run.worker?.terminate();
      this.active = null;
      this.onStatus({ kind: "error", error: String(e), id: run.id });
    };
    const attach = (url, payload) => {
      if (!current()) return;
      const worker = this.workerFactory(url);
      run.worker = worker;
      worker.onerror = (e) => {
        if (current() && run.worker === worker) fail(e.message);
      };
      worker.onmessage = async ({ data }) => {
        if (!current() || run.worker !== worker || data.id !== run.id) return;
        try {
          if (data.kind === "error") {
            fail(data.error);
            return;
          }
          if (data.kind === "execution") {
            worker.onmessage = null;
            worker.onerror = null;
            worker.terminate();
            run.execution = data;
            const receipt = {
              ...data,
              id: this.idFactory(),
              run_id: run.id,
              pie: Array.from(new Uint8Array(data.pie)),
            };
            await this.save(receipt);
            if (!current()) return;
            if (executionOnly) {
              this.active = null;
              this.onComplete(receipt);
              return;
            }
            attach("./public-prover-worker.mjs", { pie: data.pie, expectedWasm, build });
          } else if (data.kind === "proof") {
            worker.onmessage = null;
            worker.onerror = null;
            worker.terminate();
            const receipt = {
              ...data,
              id: this.idFactory(),
              run_id: run.id,
              execution_report: run.execution.report,
              execution: run.execution.execution,
              output: run.execution.output,
              anchor: run.execution.anchor,
              request: run.execution.request,
              capture_sha256: run.execution.capture.sha256,
            };
            await this.save(receipt);
            if (!current()) return;
            this.active = null;
            this.onComplete(receipt);
          } else this.onStatus(data);
        } catch (e) {
          fail(e);
        }
      };
      worker.postMessage({ id: run.id, ...payload });
    };
    try {
      attach("./public-execution-worker.mjs", { request, source });
    } catch (e) {
      fail(e);
    }
    return run.id;
  }
}
