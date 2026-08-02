import nextJest from 'next/jest.js';

const createJestConfig = nextJest({
  dir: './',
});

export default createJestConfig({
  coverageProvider: 'v8',
  testEnvironment: 'jsdom',
  setupFilesAfterEach: ['<rootDir>/jest.setup.ts'],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
});
