// Human-authored controlled guard restoration, NOT an upstream patched release.
const et = require('./lib/eTestLib');
const scenarios = require('./lib/scenarios');

et.testSet({
    desc: 'D2.4O counterfactual post-debit liquidity guard',
    preActions: scenarios.basicLiquidity(),
}).test({
    desc: 'added liquidity guard rejects debt collateral donation',
    actions: ctx => [
        { from: ctx.wallet2, send: 'dTokens.dTST.borrow', args: [0, et.eth('0.1')] },
        { from: ctx.wallet2, send: 'eTokens.eTST2.donateToReserves',
          args: [0, et.eth(10)], expectError: 'e/collateral-violation' },
        { call: 'exec.detailedLiquidity', args: [ctx.wallet2.address], onResult: r => {
            et.equals(r[1].status.collateralValue, 10 * 0.083 * .75, .0001);
            et.equals(r[0].status.liabilityValue, .1 * 2 / .4, .0001);
        } },
    ],
}).run();
