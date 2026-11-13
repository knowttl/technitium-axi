declare module '*dist/catalogue.js' {
  export const inventory: typeof import('../src/catalogue.ts').inventory;
}
declare module '*dist/read-contracts.js' {
  export const readContracts: typeof import('../src/read-contracts.ts').readContracts;
}
declare module '*dist/private-file.js' {
  export const PrivateFiles: typeof import('../src/private-file.ts').PrivateFiles;
}
declare module '*dist/vendor.js' {
  export const Redactor: typeof import('../src/vendor.ts').Redactor;
}
