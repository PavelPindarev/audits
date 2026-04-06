## EMA Price Used for Liquidation Eligibility, Spot Price Used for Collateral Seizure

**Severity:** Medium

### Summary

`ensure_liquidate_borrow_allowed` evaluates liquidation eligibility using **EMA** oracle prices (`get_price`), but `liquidate_calculate_seize_ctokens` computes collateral to seize using **spot** oracle prices (`get_spot_price`). During volatile markets where spot diverges from EMA, this inconsistency allows liquidators to seize more collateral than intended, or makes liquidations unprofitable — leading to bad debt accumulation.

### Root Cause

**Location:** [market.move:1045-1046](https://github.com/sherlock-audit/2026-03-currentsui-contest-march-2026-PavelPindarev/blob/main/sui-move-contract/contracts/protocol/sources/internal/market/market.move#L1045-L1046) vs [market.move:1115](https://github.com/sherlock-audit/2026-03-currentsui-contest-march-2026-PavelPindarev/blob/main/sui-move-contract/contracts/protocol/sources/internal/market/market.move#L1115) and [market.move:1155](https://github.com/sherlock-audit/2026-03-currentsui-contest-march-2026-PavelPindarev/blob/main/sui-move-contract/contracts/protocol/sources/internal/market/market.move#L1155)

Eligibility check uses EMA (smoothed, lag-resistant):
```move
// collaterals_value_usd_for_liquidation (line 1115)
let coin_price = get_price(x_oracle, deposit_type, oracle_base_token, clock);
// debts_value_usd_for_liquidation (line 1155)
let coin_price = get_price(x_oracle, debt_type, oracle_base_token, clock);
```

Seizure calculation uses Spot (real-time, volatile):
```move
// liquidate_calculate_seize_ctokens (lines 1045-1046)
let price_borrowed = get_spot_price(x_oracle, debt_type, oracle_base_token, clock);
let price_collateral = get_spot_price(x_oracle, collateral_type, oracle_base_token, clock);
```

From `user_oracle.move`:
- `get_price()` → returns `x_oracle.price(...).ema()` (line 29)
- `get_spot_price()` → returns `x_oracle.price(...).spot()` (line 37)

### Internal Pre-conditions

1. A liquidatable position exists (determined by EMA prices).
2. The liquidator has sufficient debt tokens to repay.

### External Pre-conditions

1. Market volatility causes EMA and spot prices to diverge. This is routine during price swings — EMA is a smoothed average that lags behind spot.

### Attack Path

**Scenario A — Liquidator extracts excess collateral:**
1. ETH collateral drops. EMA(ETH) = $2000 (lagging), Spot(ETH) = $1800 (real-time).
2. Position is liquidatable based on EMA prices.
3. Seizure calculated using Spot: `collateral_seized = debt_repaid * spot_debt / spot_collateral`.
4. Since `spot_collateral ($1800)` < `EMA_collateral ($2000)`, the liquidator seizes **more** ETH per unit of debt than the protocol's risk model intended.
5. Borrower loses more collateral than expected.

**Scenario B — Liquidation becomes unprofitable (bad debt):**
1. Debt token's spot price > EMA price temporarily.
2. EMA says the position is liquidatable, but spot-based seizure gives liquidator fewer tokens.
3. Liquidation is unprofitable → nobody liquidates → bad debt accumulates → protocol insolvency.

### Impact

- **Excess collateral extraction**: In volatile markets, liquidators seize more collateral than intended, unfairly penalizing borrowers beyond the protocol's risk parameters.
- **Bad debt accumulation**: When spot/EMA divergence makes liquidation unprofitable, undercollateralized positions go unliquidated, creating systemic risk.
- The `ema_spot_tolerance` check exists for non-liquidation operations (borrow/withdraw safety) but is not applied to the seizure calculation.

### PoC

The proof is structural — two different oracle price sources are used within the same liquidation flow.

**Eligibility check** — uses EMA via `get_price`:
```move
// collaterals_value_usd_for_liquidation (market.move:1116)
let coin_price = get_price(x_oracle, deposit_type, oracle_base_token, clock);

// debts_value_usd_for_liquidation (market.move:1156)
let coin_price = get_price(x_oracle, debt_type, oracle_base_token, clock);
```

**Seizure calculation** — uses Spot via `get_spot_price`:
```move
// liquidate_calculate_seize_ctokens (market.move:1046-1047)
let price_borrowed = get_spot_price(x_oracle, debt_type, oracle_base_token, clock);
let price_collateral = get_spot_price(x_oracle, collateral_type, oracle_base_token, clock);
```

**Oracle functions** confirm they return different price sources (`user_oracle.move`):
```move
// get_price returns EMA (line 29)
public fun get_price(...): Decimal {
    let ema = x_oracle.price(type_name, base_token).ema();
    check_price(ema, x_oracle.price_delay_tolerance_ms(), clock)
}

// get_spot_price returns Spot (line 37)
public fun get_spot_price(...): Decimal {
    let spot = x_oracle.price(type_name, base_token).spot();
    check_price(spot, x_oracle.price_delay_tolerance_ms(), clock)
}
```

Note: The existing test oracle helper (`x_oracle::update_price`) always sets EMA = Spot to the same value, so price divergence cannot be simulated in unit tests without adding a new test helper. In production, Pyth feeds EMA and Spot independently, and they routinely diverge during volatile markets.

### Mitigation

Use the same oracle source for both eligibility and seizure. Since EMA is the canonical price for risk calculations:

```diff
// In liquidate_calculate_seize_ctokens:
- let price_borrowed = get_spot_price(x_oracle, debt_type, oracle_base_token, clock);
- let price_collateral = get_spot_price(x_oracle, collateral_type, oracle_base_token, clock);
+ let price_borrowed = get_price(x_oracle, debt_type, oracle_base_token, clock);
+ let price_collateral = get_price(x_oracle, collateral_type, oracle_base_token, clock);
```
