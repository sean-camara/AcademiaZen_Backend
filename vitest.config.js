import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Node environment for backend testing
    environment: 'node',
    
    // Enable globals for describe, it, expect
    globals: true,
    
    // Test file patterns
    include: ['tests/**/*.test.{js,ts}', 'tests/**/*.spec.{js,ts}'],
    
    // Coverage configuration
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/**',
        'tests/**',
        'scripts/**',
        '*.config.js'
      ]
    },
    
    // Setup files
    setupFiles: ['./tests/setup.js'],
    
    // Timeout for tests
    testTimeout: 30000,
    
    // Hook timeout
    hookTimeout: 30000
  }
});
