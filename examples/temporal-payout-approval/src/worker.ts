import { NativeConnection, Worker } from '@temporalio/worker';
import * as activities from './activities';

const worker = await Worker.create({
  connection: await NativeConnection.connect({ address: process.env.TEMPORAL_ADDRESS ?? 'localhost:7233' }),
  taskQueue: 'payouts',
  workflowsPath: new URL('./workflows.ts', import.meta.url).pathname,
  activities,
});
console.log('worker running on task queue "payouts"');
await worker.run();
