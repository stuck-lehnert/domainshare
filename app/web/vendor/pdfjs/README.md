# Mozilla PDF.js

Pinned upstream release: [v6.3.289](https://github.com/mozilla/pdf.js/releases/tag/v6.3.289).

Runtime files originate from the legacy distribution, for broader browser compatibility:
https://github.com/mozilla/pdf.js/releases/download/v6.3.289/pdfjs-6.3.289-legacy-dist.zip

Verified ZIP SHA-256:
`51683fac4aff7dd31ed91e9ab735a2098a78d50899d1ec529aed6dc8aa19400d`

PDF.js is licensed under Apache-2.0; see `6.3.289-app1/LICENSE` and the bundled font/WASM notices.

The `6.3.289-app1` directory omits source maps and the sample PDF. Upstream JavaScript is unchanged. `web/viewer.html` selects German, restricts connections to the same origin, and loads `/assets/pdf-viewer.js` and `/assets/pdf-viewer.css` for application configuration and styling. The application disables document scripting and editing, and routes downloads through its original-file endpoint. All runtime assets are served locally. The directory suffix is a cache revision; increment it when changing bundled files.
