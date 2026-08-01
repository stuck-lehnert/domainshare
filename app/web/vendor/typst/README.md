# Vendored Typst client

The PDF report is compiled entirely in the browser. These files are kept local so report data, Typst source, fonts, and PDF output never need a third-party service or CDN.

Pinned upstream components:

- `@myriaddreamin/typst.ts@0.6.0`, `dist/esm/contrib/all-in-one-lite.bundle.js`
  - npm integrity: `sha512-IUpetG0NyF2H6eXRm4j+NsbanJHIvyrffHEijqYb6q128sLWQgT1FYJS+h7dtjXmrBEfnIl1mI80DyfDR6kB/w==`
  - upstream file SHA-256: `e884db7b1dbb3d13b85a728509e4f0b65ca36b2ee36f950406a9f77d54461cd7`
  - vendored file SHA-256: `24d3bec0e8bcf34666425c08859a1b0f15af45d5f5ad27f67132256d6ad0d958`
- `@myriaddreamin/typst-ts-web-compiler@0.6.0`, `pkg/typst_ts_web_compiler_bg.wasm`
  - npm integrity: `sha512-P/eIJ5RnfElj0NYzn5PI296t/IwWtgqUyyTMi5Jm5X3V5kZfskkH+LI7mSQe8tEyxwgCvxbxvFe5adinA3K8Gg==`
  - local SHA-256: `52995fcbcda9287b97b27996fe9b91057e4ca87fadb41b36d100bc45d33d9454`
- Libertinus Serif Regular and Semibold from `typst/typst-assets@v0.13.1`
  - Regular SHA-256: `fcf06307a77367394fcb0ccb241e59eea70dba3d732be309647611224679c733`
  - Semibold SHA-256: `a4b3f28e85881db34695c1f005e4c79233a6caf3a2bd286c9b418c025fb99308`

The immutable browser URL is revisioned as `0.6.0-csp1`; change that URL revision whenever any vendored client asset changes.

Local modification: `typst.mjs` replaces the generated `new Function` import helpers and the five fixed compiler-construction functions with native imports and explicit closures. Unknown function bodies fail closed. This lets the application keep JavaScript `'unsafe-eval'` disabled while granting only CSP `'wasm-unsafe-eval'` for the compiler itself.

Upstream sources:

- <https://github.com/Myriad-Dreamin/typst.ts>
- <https://www.npmjs.com/package/@myriaddreamin/typst.ts/v/0.6.0>
- <https://www.npmjs.com/package/@myriaddreamin/typst-ts-web-compiler/v/0.6.0>
- <https://github.com/typst/typst-assets/tree/v0.13.1>

The Typst wrapper and compiler are Apache-2.0; see `LICENSE-typst-ts`. The asset repository license is in `LICENSE-typst-assets`. The Libertinus fonts are SIL Open Font License 1.1; the applicable copyright and full license text are retained in `NOTICE-fonts`.
