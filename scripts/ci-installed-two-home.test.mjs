import assert from 'node:assert/strict';
import test from 'node:test';
import {assertCommunityMessage, assertReceivedDirect, assertSenderDelivery} from './ci-installed-two-home-journey.mjs';

test('Community proof rejects wrong text, wrong identity and the receiving Home own post', () => {
  const message = {message_id:'post:one', body:'fresh post', from_current_session:false};
  assertCommunityMessage({objects:[message]}, 'post:one', 'fresh post');
  for (const broken of [{body:'other text'}, {message_id:'post:two'}, {from_current_session:true}]) {
    assert.throws(() => assertCommunityMessage({objects:[{...message,...broken}]}, 'post:one', 'fresh post'), assert.AssertionError);
  }
});

test('Direct receive proof requires the exact incoming message and received state', () => {
  const message = {message_id:'dm:one', text:'fresh direct', direction:'incoming', delivery_state:'received'};
  assertReceivedDirect([message], 'dm:one', 'fresh direct');
  for (const broken of [{text:'other text'}, {message_id:'dm:two'}, {direction:'outgoing'}, {delivery_state:'pending'}]) {
    assert.throws(() => assertReceivedDirect([{...message,...broken}], 'dm:one', 'fresh direct'), assert.AssertionError);
  }
});

test('Sender delivered requires both the settled API state and the exact message time', () => {
  const message = {direction:'outgoing', delivery_state:'receipt_settled', created_at:42};
  assertSenderDelivery(message, '00:00');
  for (const detail of ['Sending', 'Expired', '', 'Delivered', '01:00']) {
    assert.throws(() => assertSenderDelivery(message, detail), assert.AssertionError);
  }
  for (const state of ['pending','expired','received']) {
    assert.throws(() => assertSenderDelivery({...message,delivery_state:state}, '00:00'), assert.AssertionError);
  }
});
