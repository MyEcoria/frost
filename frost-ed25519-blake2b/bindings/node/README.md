# frost-ed25519-blake2b wasm bindings

Bindings `wasm-pack` pour utiliser `frost-ed25519-blake2b` depuis TypeScript.

## Prérequis

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
npm login
```

## Build du package npm

Depuis `frost-ed25519-blake2b/bindings/node`:

```bash
wasm-pack build --release --target bundler --out-dir pkg
```

Si vous voulez publier sous scope npm (ex: `@myecoria/...`):

```bash
wasm-pack build --release --target bundler --scope myecoria --out-dir pkg
```

## API exposée

- `generate_with_dealer(max_signers, min_signers) -> DealerKeygenResult`
- `key_package_from_secret_share(secret_share_bytes) -> Uint8Array`
- `round1_commit(key_package_bytes) -> Round1CommitResult`
- `create_signing_package(commitment_list, message_bytes) -> Uint8Array`
- `round2_sign(signing_package_bytes, nonces_bytes, key_package_bytes) -> Round2SignatureShareResult`
- `aggregate_signature(signing_package_bytes, signature_share_list, public_key_package_bytes) -> Uint8Array`
- `verify_group_signature(public_key_package_bytes, message_bytes, signature_bytes) -> boolean`

Toutes les données crypto sont échangées en bytes sérialisés (`Uint8Array`).

## Structures TS (générées par wasm-bindgen)

- `DealerKeygenResult`
  - `public_key_package: Uint8Array`
  - `shares_len: number`
  - `share(index: number): DealerShare`
- `DealerShare`
  - `identifier: Uint8Array`
  - `secret_share: Uint8Array`
  - `key_package: Uint8Array`
- `Round1CommitResult`
  - `identifier: Uint8Array`
  - `nonces: Uint8Array`
  - `commitments: Uint8Array`
- `Round2SignatureShareResult`
  - `identifier: Uint8Array`
  - `signature_share: Uint8Array`
- `CommitmentList`
  - `new CommitmentList()`
  - `push(identifier, commitment)`
- `SignatureShareList`
  - `new SignatureShareList()`
  - `push(identifier, signature_share)`

## Exemple TypeScript

```ts
import init, {
  CommitmentList,
  SignatureShareList,
  aggregate_signature,
  create_signing_package,
  generate_with_dealer,
  round1_commit,
  round2_sign,
  verify_group_signature,
} from "frost-ed25519-blake2b-wasm";

await init();

const message = new TextEncoder().encode("message to sign");
const dealer = generate_with_dealer(5, 3);

const commitmentList = new CommitmentList();
const round1Results = [];

for (let i = 0; i < 3; i += 1) {
  const share = dealer.share(i);
  const round1 = round1_commit(share.key_package);
  round1Results.push({ round1, keyPackage: share.key_package });
  commitmentList.push(round1.identifier, round1.commitments);
}

const signingPackage = create_signing_package(commitmentList, message);

const signatureShareList = new SignatureShareList();
for (const item of round1Results) {
  const round2 = round2_sign(signingPackage, item.round1.nonces, item.keyPackage);
  signatureShareList.push(round2.identifier, round2.signature_share);
}

const signature = aggregate_signature(
  signingPackage,
  signatureShareList,
  dealer.public_key_package
);

const ok = verify_group_signature(dealer.public_key_package, message, signature);
console.log("signature valid:", ok);
```

## Publication npmjs

```bash
cd pkg
npm publish --access public
```

Le nom publié est basé sur `name` dans `Cargo.toml` (`frost-ed25519-blake2b-wasm`),
ou `@scope/frost-ed25519-blake2b-wasm` si `--scope` est utilisé.
