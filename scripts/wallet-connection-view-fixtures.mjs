import { readFileSync } from 'node:fs';
import { reduceConnection } from '../capsules/_shared/wallet-connection-view.mjs';

export const shared = JSON.parse(readFileSync(new URL('./fixtures/wallet-connector-v2-messages.json', import.meta.url)));
const localFixture=JSON.parse(readFileSync(new URL('./fixtures/wallet-connection-view-states.json', import.meta.url)));
export const states=localFixture.states;
export const contractStates=localFixture.contractStates;
export const unknownSafetyStates=localFixture.unknownSafetyStates.map(r=>{const original=[...states,...contractStates].find(s=>s.designState===r.fixture);return {...original,caseId:r.id,safety:r.safety,local:{...original.local,paymentPending:null},unknownSafety:true};});
const pictureFixture = JSON.parse(readFileSync(new URL('./fixtures/wallet-connection-view-pictures.json', import.meta.url)));
export const pictures = pictureFixture.states;
export const pictureViewports = pictureFixture.viewports;
const png = `data:image/png;base64,${readFileSync(new URL('./fixtures/wallet-connection-view-qr.png', import.meta.url)).toString('base64')}`;

export function fixtureArguments(row, { compact = false, sharedFixture = shared, previousFocus } = {}) {
  const packet = id => id ? sharedFixture.messages.find(r => r.id === id && r.valid)?.message : undefined;
  const canonical = sharedFixture.n7PrivateSummaries.find(r => r.id === (row.summary||row.summarySeed))?.summary;
  const summary = row.summary ? canonical : row.summarySeed ? {...canonical,...row.provisionalSummary} : row.summaryInput;
  const input = { window: row.window, stage: row.stage, account: row.local.account,
    waitSeconds: row.local.waitSeconds, localSafety: Object.hasOwn(row.local,'paymentPending')?row.local.paymentPending:false,
    homeOrigin: 'http://localhost:63198', compact, previousFocus, targetNetwork: row.provisionalInput?.targetNetwork, transactionDisplay: row.local.transactionDisplay, ...(row.local.qr ? { qrData: png } : {}) };
  return [input, { message: packet(row.provider), safetyMessage: packet(row.safety),
    summary, otherSummaries: row.otherSummaryInputs || [], alternative: row.alternative ? sharedFixture.n1Queries.find(r=>r.id===row.alternative) : undefined, nowSeconds: 1800000001 }];
}

export function fixtureView(row, options) { return reduceConnection(...fixtureArguments(row,options)); }
