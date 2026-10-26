// Independently executed original Euler V1 code on Hardhat's local EVM.
// Historical known mechanism: NOT novel; no production RPC or real assets.
const et = require('./lib/eTestLib');
const scenarios = require('./lib/scenarios');

et.testSet({
    desc: 'D2.4O real pre-incident Euler account-health control',
    preActions: scenarios.basicLiquidity(),
}).test({
    desc: 'original allows post-debit insolvent debt position',
    actions: ctx => [
        { from: ctx.wallet2, send: 'dTokens.dTST.borrow', args: [0, et.eth('0.1')] },
        { call: 'exec.detailedLiquidity', args: [ctx.wallet2.address], onResult: r => {
            et.equals(r[1].status.collateralValue, 10 * 0.083 * .75, .0001);
            et.equals(r[0].status.liabilityValue, .1 * 2 / .4, .0001);
        } },
        { from: ctx.wallet2, send: 'eTokens.eTST2.donateToReserves', args: [0, et.eth(10)] },
        { call: 'exec.detailedLiquidity', args: [ctx.wallet2.address], onResult: r => {
            et.equals(r[1].status.collateralValue, 0);
            et.equals(r[0].status.liabilityValue, .1 * 2 / .4, .0001);
        } },
    ],
}).run();
