# Vendored scripts

The page loads these from its own binary, never from the network. `TestVendoredScriptsMatchTheirPins` checks their SHA-256.

| File                   | Source                                                                                          | SHA-256                                                            |
| ---------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `htmx.min.js`          | [htmx 2.0.11](https://www.npmjs.com/package/htmx.org/v/2.0.11), `dist/htmx.min.js`              | `d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717` |
| `idiomorph-ext.min.js` | [idiomorph 0.8.0](https://www.npmjs.com/package/idiomorph/v/0.8.0), `dist/idiomorph-ext.min.js` | `5811b9a7eda14878b7dab4378bf60432e1bb6f11fcfb970cc26540642650181e` |

Both are under the Zero-Clause BSD license, in `LICENSE-htmx.txt` and `LICENSE-idiomorph.txt`. The fonts in `internal/ui/fonts` are from [Fontsource](https://fontsource.org) 5.3.0 under the SIL Open Font License, with their licenses beside them.
