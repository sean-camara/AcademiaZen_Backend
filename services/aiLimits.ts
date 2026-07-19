interface AIQuotaLimits {
  requestsPerMinute: number;
  dailyCap: number;
  monthlyCap: number;
  deepDailyCap: number;
  deepMonthlyCap?: number;
  cooldownHours?: number;
  cooldownMessages?: number;
}

interface AILimits {
  free: AIQuotaLimits;
  premium: AIQuotaLimits;
}

type Environment = Record<string, string | undefined>;

function readNonNegativeInteger(env: Environment, key: string, fallback: number): number {
  const raw = env[key];
  if (raw === undefined || raw.trim() === '') return fallback;
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

function createAILimits(env: Environment = process.env): AILimits {
  return {
    free: {
      requestsPerMinute: 5,
      dailyCap: readNonNegativeInteger(env, 'FREE_DAILY_CAP', 15),
      monthlyCap: readNonNegativeInteger(env, 'FREE_MONTHLY_CAP', 150),
      deepDailyCap: readNonNegativeInteger(env, 'FREE_DEEP_DAILY_CAP', 3),
      cooldownHours: readNonNegativeInteger(env, 'FREE_COOLDOWN_HOURS', 0),
      cooldownMessages: readNonNegativeInteger(env, 'FREE_COOLDOWN_MESSAGES', 0),
    },
    premium: {
      requestsPerMinute: 15,
      dailyCap: 30,
      monthlyCap: 300,
      deepDailyCap: 10,
      deepMonthlyCap: 40,
    },
  };
}

export { createAILimits };
export type { AILimits, AIQuotaLimits, Environment };
