import test from 'node:test';
import assert from 'node:assert/strict';
import { LoginStartup } from '../web/kernel/login-boot.js';
const state = (id = 'login', generation = 1) => ({ connected: true, coordinator: true,
  session: { id, generation, managed: null, startup: { enabled: true, state: 'pending', revision: 'r', file: '/units.json' } } });
const later = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const turns = async () => { for (let n = 0; n < 8; n++) await Promise.resolve(); };
function create(options) {
  const timers = new Map(); let id = 0;
  const controller = new LoginStartup({ begin: async () => {}, finish: async () => {}, token: () => 'private-proof',
    setTimer: (fn, ms) => { timers.set(++id, { fn, ms }); return id; }, clearTimer: id => timers.delete(id), ...options });
  return { controller, timers };
}

test('one admitted run streams bounded output and hides previous-login data', async () => {
  const done = later(); let executions = 0, output; const receipts = [];
  const { controller: c } = create({ finish: async value => receipts.push(value), execute: async (run, write) => {
    executions++; run.attached = true; output = write; return done.promise;
  } });
  c.update(state()); await turns(); c.update(state()); assert.equal(executions, 1);
  output(1, 'x'.repeat(9000)); assert.equal(c.current(state()).output.length,8192); assert.equal(c.current(state()).truncated,true);
  output(1, String.fromCodePoint(0x1f600) + 'y'.repeat(8191)); assert.equal(c.current(state()).output, 'y'.repeat(8191));
  assert.equal(c.current(state('other')).output,''); assert.equal(c.current({connected:false}).output,'');
  assert.ok(!JSON.stringify(c.current(state())).includes('private-proof'));
  const run = c.runs.get('login'); done.resolve({status:0}); await run.done;
  assert.equal(receipts[0].session,'login'); assert.equal(receipts[0].launch.proof,'private-proof');
  c.update({...state(),session:{...state().session,startup:{...state().session.startup,state:'finished'}}});
  assert.equal(executions,1);
});

test('ownership loss during admission prevents guest execution', async () => {
  const begin = later(); let executions=0; const receipts=[];
  const {controller:c}=create({begin:()=>begin.promise,execute:async()=>{executions++;return{status:0};},finish:async v=>receipts.push(v)});
  c.update(state());const run=c.runs.get('login');c.update({...state(),coordinator:false});begin.resolve();await run.done;
  assert.equal(executions,0);assert.equal(receipts[0].status,126);
});

test('a running service survives coordinator loss and shuts down on confirmed login change', async () => {
  const done=later(),signals=[];
  const {controller:c,timers}=create({execute:async run=>{run.attached=true;run.stop=()=>signals.push(15);run.job={signal:n=>signals.push(n)};return done.promise;}});
  c.update(state());await turns();const run=c.runs.get('login');
  c.update({...state(),coordinator:false});c.update({connected:false,coordinator:false,session:null});assert.deepEqual(signals,[]);
  c.update({...state('new'),coordinator:false});c.update({...state('new'),coordinator:false});assert.deepEqual(signals,[15]);
  [...timers.values()].find(timer=>timer.ms===35000).fn();assert.deepEqual(signals,[15,9]);assert.equal(run.cancelled,true);
  done.resolve({status:143});await run.done;assert.ok(![...timers.values()].some(timer=>timer.ms===35000));
});

test('a failed completion request is retried without another launch', async () => {
  let finishes=0, executions=0; const {controller:c}=create({execute:async run=>{run.attached=true;executions++;return{status:0};},
    finish:async()=>{if(++finishes===1)throw{errno:'EIO'};}});
  c.update(state());await c.runs.get('login').done;assert.equal(c.completions.size,1);
  await c.flush();assert.equal(c.completions.size,0);assert.equal(finishes,2);assert.equal(executions,1);
});

test('disabling cancels only an unstarted run', async () => {
  const wait=later();const {controller:c}=create({begin:()=>wait.promise,execute:async()=>{throw new Error('must not execute')}});
  c.update(state());const run=c.runs.get('login');c.update({...state(),session:{...state().session,startup:{...state().session.startup,enabled:false}}});
  assert.equal(run.cancelled,true);wait.resolve();await run.done;
});
