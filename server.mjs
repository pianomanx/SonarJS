#!/usr/bin/env node
import { isMainThread } from 'node:worker_threads';
import { start } from './lib/bridge/src/server.js';
import { createWorker } from './lib/shared/src/helpers/worker.js';

// import containing code which is only executed if it's a child process
import './lib/bridge/src/worker.js';

if (isMainThread) {
  /**
   * This script expects following arguments
   *
   * port - port number on which server.mjs should listen
   * host - host address on which server.mjs should listen
   * debugMemory - print memory usage
   * timeoutSeconds - timeout for the node server to wait before shutting down. If not provided or 0,
   */

  const port = process.argv[2];
  const host = process.argv[3];
  const debugMemory = process.argv[4] === 'true';
  const timeoutSeconds = Number(process.argv[5]) || 0;

  Promise.resolve().then(async () => {
    return start(
      Number.parseInt(port, 10),
      host,
      await createWorker(new URL(import.meta.url), { debugMemory }),
      debugMemory,
      timeoutSeconds,
    );
  });
}
