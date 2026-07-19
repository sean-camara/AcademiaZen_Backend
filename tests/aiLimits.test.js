const { createAILimits } = require('../dist/services/aiLimits');

describe('AI plan limits', () => {
  it('provides a useful free plan without a cooldown', () => {
    expect(createAILimits({}).free).toEqual({
      requestsPerMinute: 5,
      dailyCap: 15,
      monthlyCap: 150,
      deepDailyCap: 3,
      cooldownHours: 0,
      cooldownMessages: 0,
    });
  });

  it('allows safe production overrides', () => {
    const limits = createAILimits({
      FREE_DAILY_CAP: '20',
      FREE_MONTHLY_CAP: '200',
      FREE_DEEP_DAILY_CAP: '4',
      FREE_COOLDOWN_HOURS: '2',
      FREE_COOLDOWN_MESSAGES: '10',
    });

    expect(limits.free).toMatchObject({
      dailyCap: 20,
      monthlyCap: 200,
      deepDailyCap: 4,
      cooldownHours: 2,
      cooldownMessages: 10,
    });
  });

  it('falls back when an override is invalid', () => {
    expect(createAILimits({ FREE_DAILY_CAP: '-1' }).free.dailyCap).toBe(15);
  });
});
